/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package mistralmoderation

// Streaming responses.
//
// The engine hands a streaming policy the response in flushes. This policy holds every
// byte until the text it carries has been checked, so nothing unchecked ever reaches the
// client: text is gathered from the SSE frames, checked once enough has accumulated (the
// "text unit"), and the held bytes are released only if the check passes. On a violation the
// held bytes are dropped and the stream ends with a single error event. Bytes released by
// earlier, passing batches have already been delivered, and the HTTP status went out with
// the headers, so a mid-stream rejection cannot change it; that is a property of streaming,
// not of this policy.
//
// Each batch is checked together with the tail of the previous one (streamContextChars), so
// a phrase split across a batch boundary is still seen whole.

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"unicode/utf8"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// streamFlushPacerBytes is how many raw bytes the engine accumulates before offering a
	// flush. It paces invocation only; when a check happens is decided by the text unit.
	streamFlushPacerBytes = 4096
	// maxHeldBytes bounds what is withheld while its text is unchecked. A stream whose
	// frames carry no text (keep-alives, usage frames) never reaches the text unit, and a
	// whole-stream check (streamingTextUnitChars 0) would otherwise hold without limit.
	// Reaching it checks what has accumulated and releases.
	maxHeldBytes = 1 << 20
	// streamContextChars is how much of the previous batch is repeated in front of the next.
	streamContextChars = 200

	streamStateKey = "mistralmoderation:stream"
)

var errNoStreamState = errors.New("no shared context available for streaming state")

type streamKind int

const (
	streamUnknown  streamKind = iota
	streamSSE                 // server-sent events: checked incrementally
	streamDocument            // one JSON document sent chunked: held whole, checked at the end
	streamOpaque              // anything else: cannot be read, forwarded as is
)

// streamState is the per-response state, kept in the response's metadata so it lives and
// dies with the response.
type streamState struct {
	kind    streamKind
	held    string // raw bytes not yet released, in order
	tail    string // trailing incomplete line of held; its text has not been read yet
	pending string // extracted text not yet checked
	context string // end of the previously checked text
}

// getStreamState returns the response's state, or nil when the engine supplied no shared
// context to keep it in.
func getStreamState(respCtx *policy.ResponseStreamContext) *streamState {
	if respCtx.SharedContext == nil {
		return nil
	}
	if respCtx.Metadata == nil {
		respCtx.Metadata = map[string]interface{}{}
	}
	if st, ok := respCtx.Metadata[streamStateKey].(*streamState); ok {
		return st
	}
	st := &streamState{}
	respCtx.Metadata[streamStateKey] = st
	return st
}

// NeedsMoreResponseData tells the engine whether to keep accumulating before offering this
// policy a flush. The bytes are the raw upstream bytes.
func (p *MistralModerationPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if p.response == nil {
		return false
	}
	if looksLikeJSONDocument(accumulated) {
		return true // a unary JSON body is only readable whole
	}
	if len(accumulated) < streamFlushPacerBytes {
		return true
	}
	if looksLikeSSE(string(accumulated)) {
		return !endsAtSSEEventBoundary(accumulated) // never cut a data: line in half
	}
	return false
}

// OnResponseBodyChunk implements policy.StreamingResponsePolicy. It is called once per flush
// released by NeedsMoreResponseData, and a last time at the end of the stream.
func (p *MistralModerationPolicy) OnResponseBodyChunk(ctx context.Context, respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody, _ map[string]interface{}) policy.StreamingResponseAction {
	rp := p.response
	if rp == nil || chunk == nil || respCtx == nil {
		return policy.ForwardResponseChunk{}
	}
	if respCtx.ResponseStatus < 200 || respCtx.ResponseStatus > 299 {
		return policy.ForwardResponseChunk{} // an upstream error body is not model output
	}
	if len(chunk.Chunk) == 0 && !chunk.EndOfStream {
		return policy.ForwardResponseChunk{}
	}

	st := getStreamState(respCtx)
	if st == nil {
		// No place to hold state means the stream cannot be checked in batches. The engine
		// always supplies one, so this is an engine fault, and a guardrail fails closed.
		slog.Error("MistralModeration: no shared context on a streamed response")
		if rp.passthroughOnError {
			return policy.ForwardResponseChunk{}
		}
		return terminate(&verdict{kind: verdictCheckError, isResponse: true, params: rp,
			err: errNoStreamState}, true)
	}
	data := string(chunk.Chunk)

	if st.kind == streamUnknown {
		switch {
		case looksLikeSSE(data):
			st.kind = streamSSE
		case looksLikeJSONDocument(chunk.Chunk):
			st.kind = streamDocument
		case strings.TrimSpace(data) != "":
			st.kind = streamOpaque
			slog.Warn("MistralModeration: streamed response is neither SSE nor JSON; forwarding it unchecked")
		}
	}

	switch st.kind {
	case streamSSE:
		return p.onSSEFlush(ctx, st, data, chunk.EndOfStream, rp)
	case streamDocument:
		return p.onDocumentFlush(ctx, st, data, chunk.EndOfStream, rp)
	default:
		return policy.ForwardResponseChunk{}
	}
}

// onDocumentFlush holds a chunked JSON body whole and checks it with the same logic as a
// buffered response.
func (p *MistralModerationPolicy) onDocumentFlush(ctx context.Context, st *streamState, data string, end bool, rp *phaseParams) policy.StreamingResponseAction {
	st.held += data
	if !end {
		return policy.ForwardResponseChunk{Body: []byte{}}
	}
	body := st.held
	st.held = ""
	if v := p.moderate(ctx, []byte(body), rp, true); v != nil {
		return terminate(v, false)
	}
	return policy.ForwardResponseChunk{Body: []byte(body)}
}

// onSSEFlush reads the flush's frames into the pending text and decides whether to check
// and release now or keep holding.
func (p *MistralModerationPolicy) onSSEFlush(ctx context.Context, st *streamState, data string, end bool, rp *phaseParams) policy.StreamingResponseAction {
	st.held += data

	buf := st.tail + data
	complete, partial := splitTrailingPartialLine(buf)
	if end {
		complete, partial = buf, ""
	}
	st.tail = partial
	if texts := sseFrameTexts(complete, rp.streamPath); len(texts) > 0 {
		st.pending += strings.Join(texts, "")
	}

	pendingChars := utf8.RuneCountInString(st.pending)
	switch {
	case end:
		// last chance: check whatever is left, then release everything
	case st.pending == "":
		// nothing to check: framing only. Release what is complete.
		return release(st, end)
	case rp.streamingUnitChars > 0 && pendingChars >= rp.streamingUnitChars:
		// a full text unit has gathered
	case len(st.held) > maxHeldBytes:
		slog.Warn("MistralModeration: withheld response bytes reached the limit; checking and releasing early", "limit", maxHeldBytes)
	default:
		return policy.ForwardResponseChunk{Body: []byte{}} // keep holding
	}

	if st.pending != "" {
		if v := p.checkTexts(ctx, []string{st.context + st.pending}, rp, true); v != nil {
			st.held, st.pending = "", ""
			return terminate(v, true)
		}
		st.context = lastRunes(st.context+st.pending, streamContextChars)
		st.pending = ""
	}
	return release(st, end)
}

// release hands the client the held bytes whose text has been dealt with. Mid-stream the
// unfinished last line stays held until it completes.
func release(st *streamState, end bool) policy.StreamingResponseAction {
	out := st.held
	if end {
		st.held, st.tail = "", ""
	} else {
		out = st.held[:len(st.held)-len(st.tail)]
		st.held = st.tail
	}
	return policy.ForwardResponseChunk{Body: []byte(out)}
}

// terminate ends the stream with the verdict's error as its last event.
func terminate(v *verdict, sse bool) policy.StreamingResponseAction {
	_, body, fault := v.render()
	if sse {
		body = append(append([]byte("data: "), body...), '\n', '\n')
	}
	return policy.TerminateResponseChunk{
		Body:              body,
		AnalyticsMetadata: analyticsMetadata(v),
		IsFault:           true,
		Fault:             fault,
	}
}

// lastRunes returns the last n characters of s.
func lastRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[len(r)-n:])
}

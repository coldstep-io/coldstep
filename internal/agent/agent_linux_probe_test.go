//go:build linux

package agent

import (
	"net"
	"testing"
)

func TestMatchProbeDenyEvent_Match(t *testing.T) {
	t.Parallel()
	raw := fillTestDenyRawV4(0, 0, "probe", denyProtoTCP, denyReasonDstNotAllowlisted, probeDefendDst, probeDefendDport)
	if !matchProbeDenyEvent(raw) {
		t.Fatalf("expected match for canonical probe deny event")
	}
}

func TestMatchProbeDenyEvent_WrongDstIP(t *testing.T) {
	t.Parallel()
	raw := fillTestDenyRawV4(0, 0, "probe", denyProtoTCP, denyReasonDstNotAllowlisted, net.ParseIP("1.2.3.4"), probeDefendDport)
	if matchProbeDenyEvent(raw) {
		t.Fatalf("expected no match: different destination IP must not be confused with probe")
	}
}

func TestMatchProbeDenyEvent_WrongDport(t *testing.T) {
	t.Parallel()
	raw := fillTestDenyRawV4(0, 0, "probe", denyProtoTCP, denyReasonDstNotAllowlisted, probeDefendDst, 443)
	if matchProbeDenyEvent(raw) {
		t.Fatalf("expected no match: different destination port must not be confused with probe")
	}
}

func TestMatchProbeDenyEvent_WrongProto(t *testing.T) {
	t.Parallel()
	raw := fillTestDenyRawV4(0, 0, "probe", denyProtoUDP, denyReasonDstNotAllowlisted, probeDefendDst, probeDefendDport)
	if matchProbeDenyEvent(raw) {
		t.Fatalf("expected no match: UDP deny must not be confused with TCP probe")
	}
}

func TestMatchProbeDenyEvent_ShortBuffer(t *testing.T) {
	t.Parallel()
	if matchProbeDenyEvent(make([]byte, denyEventWireSize-1)) {
		t.Fatalf("expected no match: truncated payload must be rejected")
	}
}

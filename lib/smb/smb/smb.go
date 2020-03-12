package smb

import (
	// "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zmap/zgrab2/lib/smb/gss"
	"github.com/zmap/zgrab2/lib/smb/ntlmssp"
	"github.com/zmap/zgrab2/lib/smb/smb/encoder"
)

const ProtocolSmb = "\xFFSMB"
const ProtocolSmb2 = "\xFESMB"

const StatusOk = 0x00000000
const StatusMoreProcessingRequired = 0xc0000016
const StatusInvalidParameter = 0xc000000d
const StatusLogonFailure = 0xc000006d
const StatusUserSessionDeleted = 0xc0000203

var StatusMap = map[uint32]string{
	StatusOk:                     "OK",
	StatusMoreProcessingRequired: "More Processing Required",
	StatusInvalidParameter:       "Invalid Parameter",
	StatusLogonFailure:           "Logon failed",
	StatusUserSessionDeleted:     "User session deleted",
}

const DialectSmb_2_0_2 = 0x0202
const DialectSmb_2_1 = 0x0210
const DialectSmb_3_0 = 0x0300
const DialectSmb_3_0_2 = 0x0302
const DialectSmb_3_1_1 = 0x0311
const DialectSmb2_ALL = 0x02FF

const DialectSmb_1_0 = "\x02NT LM 0.12\x00"

const (
	CommandNegotiate uint16 = iota
	CommandSessionSetup
	CommandLogoff
	CommandTreeConnect
	CommandTreeDisconnect
	CommandCreate
	CommandClose
	CommandFlush
	CommandRead
	CommandWrite
	CommandLock
	CommandIOCtl
	CommandCancel
	CommandEcho
	CommandQueryDirectory
	CommandChangeNotify
	CommandQueryInfo
	CommandSetInfo
	CommandOplockBreak
)

const (
	_ uint16 = iota
	SecurityModeSigningEnabled
	SecurityModeSigningRequired
)

const (
	_ byte = iota
	ShareTypeDisk
	ShareTypePipe
	ShareTypePrint
)

const (
	ShareFlagManualCaching            uint32 = 0x00000000
	ShareFlagAutoCaching              uint32 = 0x00000010
	ShareFlagVDOCaching               uint32 = 0x00000020
	ShareFlagNoCaching                uint32 = 0x00000030
	ShareFlagDFS                      uint32 = 0x00000001
	ShareFlagDFSRoot                  uint32 = 0x00000002
	ShareFlagRestriceExclusiveOpens   uint32 = 0x00000100
	ShareFlagForceSharedDelete        uint32 = 0x00000200
	ShareFlagAllowNamespaceCaching    uint32 = 0x00000400
	ShareFlagAccessBasedDirectoryEnum uint32 = 0x00000800
	ShareFlagForceLevelIIOplock       uint32 = 0x00001000
	ShareFlagEnableHashV1             uint32 = 0x00002000
	ShareFlagEnableHashV2             uint32 = 0x00004000
	ShareFlagEncryptData              uint32 = 0x00008000
)

const (
	ShareCapDFS                    uint32 = 0x00000008
	ShareCapContinuousAvailability uint32 = 0x00000010
	ShareCapScaleout               uint32 = 0x00000020
	ShareCapCluster                uint32 = 0x00000040
	ShareCapAsymmetric             uint32 = 0x00000080
)

type HeaderV1 struct {
	ProtocolID       []byte `smb:"fixed:4"`
	Command          uint8
	Status           uint32
	Flags            uint8
	Flags2           uint16
	PIDHigh          uint16
	SecurityFeatures []byte `smb:"fixed:8"`
	Reserved         uint16
	TID              uint16
	PIDLow           uint16
	UID              uint16
	MID              uint16
}

type Header struct {
	ProtocolID    []byte `smb:"fixed:4"`
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	Credits       uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     []byte `smb:"fixed:16"`
}

type NegotiateReqV1 struct {
	HeaderV1
	WordCount uint8
	ByteCount uint16  // hardcoded to 14
	Dialects  []uint8 `smb:"fixed:12"`
}

type NegotiateResV1 struct {
	HeaderV1
	WordCount       uint8
	DialectIndex    uint16
	SecurityMode    uint8
	MaxMpxCount     uint16
	MaxNumberVcs    uint16
	MaxBufferSize   uint32
	MaxRawSize      uint32
	SessionKey      uint32
	Capabilities    uint32
	SystemTime      uint64
	ServerTimezon   uint16
	ChallengeLength uint8
	ByteCount       uint16
	// variable data afterwords that we don't care about
}

type NegotiateReq struct {
	Header
	StructureSize   uint16
	DialectCount    uint16 `smb:"count:Dialects"`
	SecurityMode    uint16
	Reserved        uint16
	Capabilities    uint32
	ClientGuid      []byte `smb:"fixed:16"`
	// ClientStartTime uint64
	ContextOffset   uint32
	ContextCount    uint16
	Reserved2       uint16
	Dialects        []uint16
	Reserved3       uint32
	Contexts        []byte
}

type NegotiateRes struct {
	Header
	StructureSize        uint16
	SecurityMode         uint16
	DialectRevision      uint16
	ContextCount         uint16
	ServerGuid           []byte `smb:"fixed:16"`
	Capabilities         uint32
	MaxTransactSize      uint32
	MaxReadSize          uint32
	MaxWriteSize         uint32
	SystemTime           uint64
	ServerStartTime      uint64
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	ContextOffset        uint32
	SecurityBlob         *gss.NegTokenInit
}

type SessionSetup1Req struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         *gss.NegTokenInit
}

type SessionSetup1Res struct {
	Header
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         *gss.NegTokenResp
}

type SessionSetup2Req struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         *gss.NegTokenResp
}

type SessionSetup2Res struct {
	Header
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         *gss.NegTokenResp
}

type TreeConnectReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
	PathOffset    uint16 `smb:"offset:Path"`
	PathLength    uint16 `smb:"len:Path"`
	Path          []byte
}

type TreeConnectRes struct {
	Header
	StructureSize uint16
	ShareType     byte
	Reserved      byte
	ShareFlags    uint32
	Capabilities  uint32
	MaximalAccess uint32
}

type TreeDisconnectReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type TreeDisconnectRes struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

func newHeaderV1() HeaderV1 {
	return HeaderV1{
		ProtocolID: []byte(ProtocolSmb),
	}
}

func newHeader() Header {
	return Header{
		ProtocolID:    []byte(ProtocolSmb2),
		StructureSize: 64,
		CreditCharge:  0,
		Status:        0,
		Command:       0,
		Credits:       0,
		Flags:         0,
		NextCommand:   0,
		MessageID:     0,
		Reserved:      0,
		TreeID:        0,
		SessionID:     0,
		Signature:     make([]byte, 16),
	}
}

func (s *Session) NewNegotiateReqV1() NegotiateReqV1 {
	header := newHeaderV1()
	header.Command = 0x72 // SMB1 Negotiate
	return NegotiateReqV1{
		HeaderV1:  header,
		WordCount: 0,
		ByteCount: 14,
		Dialects:  []uint8(DialectSmb_1_0),
	}
}

func (s *Session) NewNegotiateReq() NegotiateReq {
	header := newHeader()
	header.Command = CommandNegotiate
	header.CreditCharge = 1
	header.MessageID = s.messageID

	dialects := []uint16{
		uint16(DialectSmb_2_1),
		uint16(DialectSmb_3_0),
		uint16(DialectSmb_3_0_2),
		uint16(DialectSmb_3_1_1),
	}
	guid := make([]byte, 16)
	// rand.Read(guid)
	copy(guid, "cve20200796-scan")

	// taken from a smbclient request as i did not want to build it myself
	//  should probably at least swap out / generate the integrity salt in there
	// contextblob, _ := hex.DecodeString("0100260000000000010020000100750605ed60889ecb5e79bbe84459c55cd2825106327a6e2e41c5a83fddf2c518000002000600000000000200010002000000" + "03001000" + "00000000" + "0400" + "000000000000" + "0100020003000400" + "05001c00000000003100390032002e003100360038002e003100370038002e0032003100")
	contextblob, _ := hex.DecodeString("0100260000000000010020000100750605ed60889ecb5e79bbe84459c55cd2825106327a6e2e41c5a83fddf2c518000002000600000000000200010002000000" + "03001000" + "00000000" + "0400" + "000000000000" + "0100020003000400")
	return NegotiateReq{
		Header:          header,
		StructureSize:   36,
		DialectCount:    uint16(len(dialects)),
		// SecurityMode:    SecurityModeSigningEnabled,
		SecurityMode:    0,
		Reserved:        0,
		// Capabilities:    0x7f,
		Capabilities:    0,
		ClientGuid:      guid,
		ContextOffset:   0x70,
		ContextCount:    3,
		Reserved2:       0,
		Dialects:        dialects,
		Reserved3:       0,
		// Reserved4:       0,
		Contexts:        contextblob,
	}
}

func NewNegotiateRes() NegotiateRes {
	return NegotiateRes{
		Header:               newHeader(),
		StructureSize:        0,
		SecurityMode:         0,
		DialectRevision:      0,
		ContextCount:         0,
		ServerGuid:           make([]byte, 16),
		Capabilities:         0,
		MaxTransactSize:      0,
		MaxReadSize:          0,
		MaxWriteSize:         0,
		SystemTime:           0,
		ServerStartTime:      0,
		SecurityBufferOffset: 0,
		SecurityBufferLength: 0,
		ContextOffset:        0,
		SecurityBlob:         &gss.NegTokenInit{},
	}
}

func (s *Session) NewSessionSetup1Req() (SessionSetup1Req, error) {
	header := newHeader()
	header.Command = CommandSessionSetup
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID

	ntlmsspneg := ntlmssp.NewNegotiate(s.options.Domain, s.options.Workstation)
	data, err := encoder.Marshal(ntlmsspneg)
	if err != nil {
		return SessionSetup1Req{}, err
	}

	if s.sessionID != 0 {
		return SessionSetup1Req{}, errors.New("Bad session ID for session setup 1 message")
	}

	// Initial session setup request
	init, err := gss.NewNegTokenInit()
	if err != nil {
		return SessionSetup1Req{}, err
	}
	init.Data.MechToken = data

	return SessionSetup1Req{
		Header:               header,
		StructureSize:        25,
		Flags:                0x00,
		SecurityMode:         byte(SecurityModeSigningEnabled),
		Capabilities:         0,
		Channel:              0,
		SecurityBufferOffset: 88,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		SecurityBlob:         &init,
	}, nil
}

func NewSessionSetup1Res() (SessionSetup1Res, error) {
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup1Res{}, err
	}
	ret := SessionSetup1Res{
		Header:       newHeader(),
		SecurityBlob: &resp,
	}
	return ret, nil
}

func (s *Session) NewSessionSetup2Req() (SessionSetup2Req, error) {
	header := newHeader()
	header.Command = CommandSessionSetup
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID

	ntlmsspneg := ntlmssp.NewNegotiate(s.options.Domain, s.options.Workstation)
	data, err := encoder.Marshal(ntlmsspneg)
	if err != nil {
		return SessionSetup2Req{}, err
	}

	if s.sessionID == 0 {
		return SessionSetup2Req{}, errors.New("Bad session ID for session setup 2 message")
	}

	// Session setup request #2
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup2Req{}, err
	}
	resp.ResponseToken = data

	return SessionSetup2Req{
		Header:               header,
		StructureSize:        25,
		Flags:                0x00,
		SecurityMode:         byte(SecurityModeSigningEnabled),
		Capabilities:         0,
		Channel:              0,
		SecurityBufferOffset: 88,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		SecurityBlob:         &resp,
	}, nil
}

func NewSessionSetup2Res() (SessionSetup2Res, error) {
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup2Res{}, err
	}
	ret := SessionSetup2Res{
		Header:       newHeader(),
		SecurityBlob: &resp,
	}
	return ret, nil
}

// NewTreeConnectReq creates a new TreeConnect message and accepts the share name
// as input.
func (s *Session) NewTreeConnectReq(name string) (TreeConnectReq, error) {
	header := newHeader()
	header.Command = CommandTreeConnect
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID

	path := fmt.Sprintf("\\\\%s\\%s", s.options.Host, name)
	return TreeConnectReq{
		Header:        header,
		StructureSize: 9,
		Reserved:      0,
		PathOffset:    0,
		PathLength:    0,
		Path:          encoder.ToUnicode(path),
	}, nil
}

func NewTreeConnectRes() (TreeConnectRes, error) {
	return TreeConnectRes{}, nil
}

func (s *Session) NewTreeDisconnectReq(treeId uint32) (TreeDisconnectReq, error) {
	header := newHeader()
	header.Command = CommandTreeDisconnect
	header.CreditCharge = 1
	header.MessageID = s.messageID
	header.SessionID = s.sessionID
	header.TreeID = treeId

	return TreeDisconnectReq{
		Header:        header,
		StructureSize: 4,
		Reserved:      0,
	}, nil
}

func NewTreeDisconnectRes() (TreeDisconnectRes, error) {
	return TreeDisconnectRes{}, nil
}

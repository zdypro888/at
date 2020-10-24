package at

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/zdypro888/workspace/done/at/pdu"
)

// Encoding is an encoding option to use.
type Encoding byte

// Encodings represents all the supported encodings.
var Encodings = struct {
	Gsm7Bit Encoding
	UCS2    Encoding
}{
	15, 72,
}

//USSDType ussd report
type USSDType int

//USSD Types
const (
	USSDDisabled USSDType = 0
	USSDEnabled  USSDType = 1
	USSDExit     USSDType = 2
)

// USSD type represents the USSD query string
type USSD string

// Encode converts the query string into bytes according to the
// specified encoding.
func (u *USSD) Encode(enc Encoding) ([]byte, error) {
	switch enc {
	case Encodings.Gsm7Bit:
		return pdu.Encode7Bit(u.String()), nil
	case Encodings.UCS2:
		return pdu.EncodeUcs2(u.String()), nil
	default:
		return nil, ErrUnknownEncoding
	}
}

func (u *USSD) String() string {
	return string(*u)
}

type ussdReport struct {
	N      uint64
	Octets []byte
	Enc    Encoding
}

func (r *ussdReport) Parse(str string) error {
	var err error
	fields := strings.Split(str, ",")
	if len(fields) < 3 {
		return ErrParseReport
	}
	if r.N, err = strconv.ParseUint(fields[0], 10, 8); err != nil {
		return err
	}
	if r.Octets, err = hex.DecodeString(strings.Trim(fields[1], `"`)); err != nil {
		return err
	}
	var e uint64
	if e, err = strconv.ParseUint(fields[2], 10, 8); err != nil {
		return err
	}
	r.Enc = Encoding(e)
	return nil
}

//MemoryType sms stored
type MemoryType string

//MemoryTypes
const (
	MTNvRAM       MemoryType = "ME" //"NV RAM"
	MTAssociated  MemoryType = "MT" //"ME-associated storage"
	MTSim         MemoryType = "SM" //"Sim message storage"
	MTStateReport MemoryType = "SR" //"State report storage"
)

type messageReport struct {
	Memory MemoryType
	Index  uint64
}

func (m *messageReport) Parse(str string) error {
	fields := strings.Split(str, ",")
	if len(fields) < 2 {
		return ErrParseReport
	}
	//这里可能存在MemoryType未知
	m.Memory = MemoryType(strings.Trim(fields[0], `"`))
	var err error
	m.Index, err = strconv.ParseUint(fields[1], 10, 16)
	return err
}

type signalStrengthReport uint64

func (s *signalStrengthReport) Parse(str string) (err error) {
	var u uint64
	u, err = strconv.ParseUint(str, 10, 8)
	*s = signalStrengthReport(u)
	return
}

type bootHandshakeReport uint64

func (b *bootHandshakeReport) Parse(str string) (err error) {
	fields := strings.Split(str, ",")
	if len(fields) < 1 {
		return ErrParseReport
	}
	var key uint64
	if key, err = strconv.ParseUint(fields[0], 10, 8); err != nil {
		return
	}
	*b = bootHandshakeReport(key)
	return
}

//ModeType 猫池种类
type ModeType int

//ModeTypes
const (
	MNoService ModeType = 0  //"No service"
	MAMPS      ModeType = 1  //"AMPS"
	MCDMA      ModeType = 2  //"CDMA"
	MGsmGprs   ModeType = 3  ///"GSM/GPRS"
	MHDR       ModeType = 4  //"HDR"
	MWCDMA     ModeType = 5  //"WCDMA"
	MGPS       ModeType = 6  //"GPS"
	MGsmWcdma  ModeType = 7  //"GSM/WCDMA"
	MCdmaHdr   ModeType = 8  //"CDMA/HDR HYBRID"
	MSCDMA     ModeType = 15 //"TD-SCDMA"
)

//Parse parse
func (s *ModeType) Parse(str string) (err error) {
	var o uint64
	if o, err = strconv.ParseUint(str, 10, 8); err != nil {
		return
	}
	*s = ModeType(int(o))
	return
}

//SubModeType 二级
type SubModeType int

//SubModeTypes
const (
	SMSMNoService SubModeType = 0
	SMGSM         SubModeType = 1
	SMGPRS        SubModeType = 2
	SMEDGE        SubModeType = 3
	SMWCDMA       SubModeType = 4
	SMHSDPA       SubModeType = 5
	SMHSUPA       SubModeType = 6
	SMHsdpaHsupa  SubModeType = 7
	SMSCDMA       SubModeType = 8
	SMHspaPlus    SubModeType = 9
	SMHspa64QAM   SubModeType = 17
	SMHspaMIMO    SubModeType = 18
)

//Parse parse
func (s *SubModeType) Parse(str string) (err error) {
	var o uint64
	if o, err = strconv.ParseUint(str, 10, 8); err != nil {
		return
	}
	*s = SubModeType(int(o))
	return
}

type modeReport struct {
	Mode    ModeType
	Submode SubModeType
}

func (m *modeReport) Parse(str string) (err error) {
	fields := strings.Split(str, ",")
	if len(fields) < 2 {
		return ErrParseReport
	}
	var mode, submode uint64
	if mode, err = strconv.ParseUint(fields[0], 10, 8); err != nil {
		return
	}
	if submode, err = strconv.ParseUint(fields[0], 10, 8); err != nil {
		return
	}
	m.Mode = ModeType(int(mode))
	m.Submode = SubModeType(int(submode))
	return
}

//ServiceType 服务状态
type ServiceType int

//ServiceStates
const (
	SSNone               ServiceType = 0 //No service
	SSRestricted         ServiceType = 1 //Restricted service
	SSValid              ServiceType = 2 //Valid service
	SSRestrictedRegional ServiceType = 3 //Restricted regional service
	SSPowerSaving        ServiceType = 4 //Power-saving and deep sleep state
)

//Parse parse
func (s *ServiceType) Parse(str string) (err error) {
	var o uint64
	if o, err = strconv.ParseUint(str, 10, 8); err != nil {
		return
	}
	*s = ServiceType(int(o))
	return
}

//SimType 卡状态
type SimType int

//SimStates
const (
	SIMInvalid     SimType = 0   //Invalid USIM card or pin code locked
	SIMValid       SimType = 1   //Valid USIM card
	SIMInvalidCS   SimType = 2   //USIM is invalid for cellular service
	SIMInvalidPS   SimType = 3   //USIM is invalid for packet service
	SIMInvalidCSPS SimType = 4   //USIM is not valid for cellular nor packet services
	SIMNoCard      SimType = 255 //USIM card is not exist
)

//Parse parse
func (s *SimType) Parse(str string) (err error) {
	var o uint64
	if o, err = strconv.ParseUint(str, 10, 8); err != nil {
		return
	}
	*s = SimType(int(o))
	return
}

//DomainType domain type
type DomainType int

//ServiceDomains
const (
	DTNone               DomainType = 0 //No service
	DTRestricted         DomainType = 1 //Cellular service only
	DTValid              DomainType = 2 //Packet service only
	DTRestrictedRegional DomainType = 3 //Packet and Cellular services
	DTPowerSaving        DomainType = 4 //Searching
)

//Parse parse
func (s *DomainType) Parse(str string) (err error) {
	var o uint64
	if o, err = strconv.ParseUint(str, 10, 8); err != nil {
		return
	}
	*s = DomainType(int(o))
	return
}

//RoamingType Roaming type
type RoamingType int

//RoamingStates
const (
	NotRoaming RoamingType = 0
	Roaming    RoamingType = 1
)

//Parse parse
func (s *RoamingType) Parse(str string) (err error) {
	var o uint64
	if o, err = strconv.ParseUint(str, 10, 8); err != nil {
		return
	}
	*s = RoamingType(int(o))
	return
}

//DeleteOption DeleteOptions
type DeleteOption int

//DeleteOptions
const (
	//Delete message by index
	DelIndex DeleteOption = 0
	//Delete all read messages except MO
	DelAllReadNotMO DeleteOption = 1
	//Delete all read messages except unsent MO
	DelAllReadNotUnsent DeleteOption = 2
	//Delete all except unread
	DelAllNotUnread DeleteOption = 3
	//Delete all messages
	DelAll DeleteOption = 4
)

//MessageFlag message flag
type MessageFlag int

//MessageFlags
const (
	MFUnread MessageFlag = 0
	MFRead   MessageFlag = 1
	MFUnsent MessageFlag = 2
	MFSent   MessageFlag = 3
	MFAny    MessageFlag = 4
)

// SystemInfoReport represents the report from the AT^SYSINFO command.
type SystemInfoReport struct {
	ServiceState  ServiceType
	ServiceDomain DomainType
	RoamingState  RoamingType
	SystemMode    ModeType
	SystemSubmode SubModeType
	SimState      SimType
}

// Parse scans the AT^SYSINFO report into a non-nil SystemInfoReport struct.
func (s *SystemInfoReport) Parse(str string) error {
	fields := strings.Split(str, ",")
	if len(fields) < 5 {
		return ErrParseReport
	}
	if err := s.ServiceState.Parse(fields[0]); err != nil {
		return err
	}
	if err := s.ServiceDomain.Parse(fields[1]); err != nil {
		return err
	}
	if err := s.RoamingState.Parse(fields[2]); err != nil {
		return err
	}
	if err := s.SystemMode.Parse(fields[3]); err != nil {
		return err
	}
	if err := s.SimState.Parse(fields[4]); err != nil {
		return err
	}
	if len(fields) > 6 {
		if err := s.SystemSubmode.Parse(fields[0]); err != nil {
			return err
		}
	}
	return nil
}

package at

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kardianos/osext"
	"github.com/tarm/serial"
	"github.com/zdypro888/at/pdu"
	"github.com/zdypro888/at/sms"
)

// Sep <CR><LF> sequence.
const Sep = "\r\n"

// SepBytes <CR><LF> sequence.
var SepBytes = []byte("\r\n")

// RSep <LF><CR> sequence.
const RSep = "\n\r"

// RSepBytes <LF><CR> sequence.
var RSepBytes = []byte("\n\r")

// InteractiveBytes CMGS 中间
var InteractiveBytes = []byte("> ")

// Sub Ctrl+Z code.
const Sub = string(0x1A)

const (
	atTimeout = 20 * time.Second
)

// Common errors.
var (
	ErrTimeout         = errors.New("at: timeout")
	ErrUnknownEncoding = errors.New("at: unsupported encoding")
	ErrClosed          = errors.New("at: device ports are closed")
	ErrNotInitialized  = errors.New("at: not initialized")
	ErrWriteFailed     = errors.New("at: write failed")
	ErrParseReport     = errors.New("at: error while parsing report")
	ErrUnknownReport   = errors.New("at: got unknown report")
)

// DeviceState represents the device state including cellular options,
// signal quality, current operator name, service status.
type DeviceState struct {
	ServiceState   ServiceType
	ServiceDomain  DomainType
	RoamingState   RoamingType
	SystemMode     ModeType
	SystemSubmode  SubModeType
	SimState       SimType
	ModelName      string
	OperatorName   string
	IMEI           string
	MEID           string
	SignalStrength int
}

type kindType int

const (
	ktPrompt  kindType = 1
	ktPrefix  kindType = 2
	ktMessage kindType = 3
)

type recved struct {
	Kind kindType
	Line string
}
type request struct {
	Data []byte
}
type replyInfo struct {
	Err   error
	Reply string
}

type response struct {
	Waiter chan *replyInfo
}

// Modem 猫池
type Modem struct {
	connection   io.ReadWriteCloser
	notifycation chan string
	recvedChan   chan *recved
	requestChan  chan *request
	responseChan chan *response
	gowaiter     *sync.WaitGroup
	running      bool

	Notifycation bool
	State        *DeviceState
	USSD         chan USSD
	Message      chan *sms.Message
	LRCPIN       string
	LRCREG       string
	LRCSCA       string
	LRCIMI       string

	Debug      int
	loggerText *log.Logger
	loggerDat  *log.Logger
}

// NewModem 创建新的 modem
func NewModem(debug int) *Modem {
	m := &Modem{
		notifycation: make(chan string),
		recvedChan:   make(chan *recved),
		requestChan:  make(chan *request, 1),
		responseChan: make(chan *response, 1),
		gowaiter:     &sync.WaitGroup{},
		State:        &DeviceState{},
		USSD:         make(chan USSD, 16),
		Message:      make(chan *sms.Message, 16),
		Debug:        debug,
	}
	return m
}

func (m *Modem) isCDMA() bool {
	return m.State.SystemMode == MCDMA
}

func (m *Modem) printf(format string, args ...any) {
	if m.Debug&1 == 1 {
		log.Printf(format, args...)
	}
	if m.Debug&2 == 2 {
		m.loggerText.Printf(format, args...)
	}
}

func (m *Modem) notify(reply string, err error) {
	var res *response
	select {
	case res = <-m.responseChan:
		m.printf("检测到结果等待")
		res.Waiter <- &replyInfo{Reply: strings.TrimSuffix(reply, Sep), Err: err}
	default:
		m.printf("无结果等待放弃: %v", err)
	}
}

func (m *Modem) sendWait(text string) (string, error) {
	return m.sendTextWait(text + Sep)
}
func (m *Modem) sendTextWait(text string) (string, error) {
	res := &response{Waiter: make(chan *replyInfo)}
	defer close(res.Waiter)
	m.responseChan <- res
	m.requestChan <- &request{Data: []byte(text)}
	select {
	case reply := <-res.Waiter:
		return reply.Reply, reply.Err
	case <-time.After(atTimeout):
		select {
		case reply := <-res.Waiter:
			return reply.Reply, reply.Err
		case <-m.responseChan:
			return "", ErrTimeout
		}
	}
}

func (m *Modem) sendInteractive(part1, part2 string) error {
	if _, err := m.sendTextWait(part1 + "\r" /*不使用Sep*/); err != nil {
		return err
	}
	if _, err := m.sendTextWait(part2 + Sub); err != nil {
		return err
	}
	return nil
}

// Connect 连接
func (m *Modem) Connect(tag, address string, baud int) error {
	var err error
	if m.Debug != 0 {
		var folder string
		if folder, err = osext.ExecutableFolder(); err != nil {
			return err
		}
		var logFile, bufFile *os.File
		if logFile, err = os.OpenFile(path.Join(folder, "logs", fmt.Sprintf("LOG_%s.txt", tag)), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_SYNC, 0666); err != nil {
			return err
		}
		if bufFile, err = os.OpenFile(path.Join(folder, "logs", fmt.Sprintf("DAT_%s.txt", tag)), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_SYNC, 0666); err != nil {
			return err
		}
		m.loggerText = log.New(logFile, "", log.Ldate|log.Ltime)
		m.loggerDat = log.New(bufFile, "", log.Ldate|log.Ltime)
	}
	if strings.HasPrefix(address, "tcp://") {
		m.connection, err = net.Dial("tcp", strings.TrimPrefix(address, "tcp://"))
	} else {
		c := &serial.Config{Name: address, Baud: baud}
		m.connection, err = serial.OpenPort(c)
	}
	if err == nil {
		m.running = true
		m.gowaiter.Add(2)
		go m.watchGo()
		go m.handleGo()
	}
	return err
}

// Close 关闭
func (m *Modem) Close() {
	if m.connection != nil {
		m.connection.Close()
	}
	m.running = false
	m.gowaiter.Wait()
}

func (m *Modem) handleGo() {
	defer m.gowaiter.Done()
	var err error
	var rlen, length int
	data := make([]byte, 0x1000)
	for m.running {
		if len(data) == length {
			ndata := make([]byte, length*2)
			copy(ndata, data)
			data = ndata
		}
		if rlen, err = m.connection.Read(data[length:]); err != nil {
			m.printf("接收数据错误: %v", err)
			break
		}
		if m.Debug&2 == 2 {
			recvText := string(data[length : length+rlen])
			messageText := strings.ReplaceAll(strings.ReplaceAll(recvText, "\r", "\\r"), "\n", "\\n")
			m.loggerDat.Printf(messageText)
			m.printf("接收: %s", messageText)
		}
		length += rlen
		databuf := data[:length]
		continueRecv := false
		for m.running && len(databuf) > 0 && !continueRecv {
			if databuf[0] == 0xFF {
				databuf = databuf[1:]
			} else if bytes.HasPrefix(databuf, InteractiveBytes) {
				m.recvedChan <- &recved{Kind: ktPrompt}
				databuf = databuf[len(InteractiveBytes):]
			} else if bytes.HasPrefix(databuf, RSepBytes) && !bytes.HasPrefix(databuf[1:], SepBytes) {
				//F1: 这类主动状态上报
				lineLast := len(RSepBytes)
				for {
					if index := bytes.Index(databuf[lineLast:], RSepBytes); index != -1 {
						index += lineLast + len(RSepBytes)
						line := strings.TrimSpace(string(databuf[lineLast:index]))
						lineLast = index
						m.notifycation <- line
						if bytes.HasPrefix(databuf[index:], RSepBytes) {
							databuf = databuf[index+len(RSepBytes):]
							break
						}
					} else {
						continueRecv = true
						break
					}
				}
			} else if index := bytes.Index(databuf, SepBytes); index != -1 {
				index += len(SepBytes)
				line := strings.TrimSpace(string(databuf[:index]))
				if line != "" {
					if strings.HasPrefix(line, "AT") {
						m.recvedChan <- &recved{Kind: ktPrefix, Line: line}
					} else {
						m.recvedChan <- &recved{Kind: ktMessage, Line: line}
					}
				}
				databuf = databuf[index:]
			} else {
				continueRecv = true
			}
		}
		if dataLen := len(databuf); dataLen != length {
			if dataLen > 0 {
				copy(data, databuf)
			}
			length = dataLen
		}
	}
}

func (m *Modem) watchGo() {
	defer m.gowaiter.Done()
	var err error
	var reply strings.Builder
	for m.running {
		select {
		case req := <-m.requestChan:
			m.printf("开始发送: %s", string(req.Data))
			if _, err = m.connection.Write(req.Data); err != nil {
				m.printf("发送失败: %v", err)
				m.running = false
			}
		case notify := <-m.notifycation:
			m.printf("上报信息: %s", notify)
		case response := <-m.recvedChan:
			m.printf("内容(%d): %s", response.Kind, response.Line)
			switch response.Kind {
			case ktPrompt:
				m.notify("", nil)
			case ktPrefix:

			case ktMessage:
				infos := strings.SplitN(response.Line, ":", 2)
				switch strings.ToUpper(strings.TrimSpace(infos[0])) {
				//命令结果返回
				case "AT": // "Noop"
					m.notify(reply.String(), nil)
					reply.Reset()
				case "OK": // "Success":
					m.notify(reply.String(), nil)
					reply.Reset()
				case "ERROR": // "Error":
					m.notify(reply.String(), errors.New("Error"))
					reply.Reset()
				case "+CME ERROR": // "CME Error":
					if len(infos) == 2 {
						m.notify(reply.String(), ERRCME(infos[1]))
					} else {
						m.notify(reply.String(), errors.New(response.Line))
					}
					reply.Reset()
				case "+CMS ERROR": // "CMS Error":
					if len(infos) == 2 {
						m.notify(reply.String(), ERRCMS(infos[1]))
					} else {
						m.notify(reply.String(), errors.New(response.Line))
					}
					reply.Reset()
				case "AT_KILL": // "Timeout":
					m.notify(reply.String(), ErrTimeout)
					reply.Reset()
				//其它不需要处理
				case "CALL READY":
				//服务器主动返回
				case "^RSSI": // "Signal strength":
					if len(infos) == 2 {
						var rssi signalStrengthReport
						if err = rssi.Parse(infos[1]); err != nil {
							m.printf("解析RSSI错误: %v", err)
						} else {
							m.State.SignalStrength = int(rssi)
						}
					} else {
						m.printf("错误的RSSI命令: %s", response.Line)
					}
				case "^BOOT": // "Boot handshake":
					if len(infos) == 2 {
						var token bootHandshakeReport
						if err = token.Parse(infos[1]); err != nil {
							m.printf("解析BOOT错误: %v", err)
						} else {
							go func() {
								m.BOOT(uint64(token))
							}()
						}
					} else {
						m.printf("错误的BOOT命令: %s", response.Line)
					}
				case "^MODE": // "System mode":
					if len(infos) == 2 {
						var report modeReport
						if err = report.Parse(infos[1]); err != nil {
							m.printf("解析MODE错误: %v", err)
						} else {
							m.State.SystemMode = report.Mode
							m.State.SystemSubmode = report.Submode
						}
					} else {
						m.printf("错误的MODE命令: %s", response.Line)
					}
				case "^SRVST": // "Service state":
					if len(infos) == 2 {
						var report ServiceType
						if err = report.Parse(infos[1]); err != nil {
							m.printf("解析SRVST错误: %v", err)
						} else {
							m.State.ServiceState = report
						}
					} else {
						m.printf("错误的SRVST命令: %s", response.Line)
					}
				case "^SIMST": // "Sim state":.
					if len(infos) == 2 {
						var report SimType
						if err = report.Parse(infos[1]); err != nil {
							m.printf("解析SIMST错误: %v", err)
						} else {
							m.State.SimState = report
						}
					} else {
						m.printf("错误的SIMST命令: %s", response.Line)
					}
				case "^STIN": // "STIN":
					if len(infos) == 2 {
					} else {
						m.printf("错误的STIN命令: %s", response.Line)
					}
				case "+CFUN": // "CFUN":
					if len(infos) == 2 {
					} else {
						m.printf("错误的CFUN命令: %s", response.Line)
					}
				case "+STKPCI": // "STK Menu":
					if len(infos) == 2 {
					} else {
						m.printf("错误的STKPCI命令: %s", response.Line)
					}
				//命令内容返回
				case "^SYSINFO":
					if len(infos) == 2 {
						sir := new(SystemInfoReport)
						if err = sir.Parse(strings.TrimSpace(infos[1])); err != nil {
							m.printf("解析SYSINFO错误: %v", err)
						} else {
							m.State.ServiceState = sir.ServiceState
							m.State.ServiceDomain = sir.ServiceDomain
							m.State.RoamingState = sir.RoamingState
							m.State.SystemMode = sir.SystemMode
							m.State.SystemSubmode = sir.SystemSubmode
							m.State.SimState = sir.SimState
						}
					} else {
						m.printf("错误的SYSINFO命令: %s", response.Line)
					}
				case "+COPS":
					if len(infos) == 2 {
						if fields := strings.Split(strings.TrimSpace(infos[1]), ","); len(fields) >= 3 {
							m.State.OperatorName = strings.TrimLeft(strings.TrimRight(fields[2], `"`), `"`)
						}
					} else {
						m.printf("错误的COPS命令: %s", response.Line)
					}
				case "+GMM", "+CGMM":
					if len(infos) == 2 {
						m.State.ModelName = strings.TrimSpace(infos[1])
					} else {
						m.printf("错误的GMM命令: %s", response.Line)
					}
				case "+CPIN":
					if len(infos) == 2 {
						m.LRCPIN = strings.TrimSpace(infos[1])
					} else {
						m.printf("错误的CPIN命令: %s", response.Line)
					}
				case "+CPMS":
					if len(infos) == 2 {
						//0,5,0,5,0,5
					} else {
						m.printf("错误的CPMS命令: %s", response.Line)
					}
				case "+CGSN":
					if len(infos) == 2 {
						m.State.IMEI = strings.TrimSpace(infos[1])
					} else {
						m.printf("错误的CGSN命令: %s", response.Line)
					}
				case "+CIMI":
					if len(infos) == 2 {
						m.LRCIMI = strings.TrimSpace(infos[1])
					} else {
						m.printf("错误的CIMI命令: %s", response.Line)
					}
				case "^MEID":
					if len(infos) == 2 {
						m.State.MEID = strings.TrimSpace(infos[1])
					} else {
						m.printf("错误的MEID命令: %s", response.Line)
					}
				case "+CREG":
					if len(infos) == 2 {
						m.LRCREG = strings.TrimSpace(infos[1])
					} else {
						m.printf("错误的CREG命令: %s", response.Line)
					}
				case "+CSCA":
					if len(infos) == 2 {
						cscaInfos := strings.Split(strings.TrimSpace(infos[1]), ",")
						m.LRCSCA = strings.Trim(cscaInfos[0], "\"")
					} else {
						m.printf("错误的CSCA命令: %s", response.Line)
					}
				case "+CUSD": // "USSD reply":
					if len(infos) == 2 {
						var ussd ussdReport
						if err = ussd.Parse(infos[1]); err != nil {
							m.printf("解析USSD错误: %v", err)
						} else {
							var text string
							if ussd.Enc == Encodings.UCS2 {
								if text, err = pdu.DecodeUcs2(ussd.Octets, false); err != nil {
									m.printf("解析USSD内容错误(UCS2): %v", err)
								} else {
									m.USSD <- USSD(text)
								}
							} else if ussd.Enc == Encodings.Gsm7Bit {
								if text, err = pdu.Decode7Bit(ussd.Octets); err != nil {
									m.printf("解析USSD内容错误(7Bit): %v", err)
								} else {
									m.USSD <- USSD(text)
								}
							} else {
								m.printf("错误的USSD编码: %d", ussd.Enc)
							}
						}
					} else {
						m.printf("错误的USSD命令: %s", response.Line)
					}
				case "+CMGS":
					if len(infos) == 2 {
						//CMGS 发送结果 ID 整数形
					} else {
						m.printf("错误的CMGS命令: %s", response.Line)
					}
				case "+CMTI": // "Incoming SMS":
					if len(infos) == 2 {
						var report messageReport
						if err = report.Parse(infos[1]); err != nil {
							m.printf("解析CMTI错误: %v", err)
						} else {
							go func() {
								if err := m.CMGR(report.Index); err != nil {
									m.printf("获取新短信错误: %v", err)
									if err = m.CMGD(report.Index, DelIndex); err != nil {
										fmt.Printf("删除新短信出错: %v", err)
									}
								}
							}()
						}
					} else {
						m.printf("错误的CMTI命令: %s", response.Line)
					}
				case "+CMGR":
					if len(infos) == 2 {
						//message_status,address,[address_text][,address_type,TPDU_first_octet,protocol_identifier,data_coding_scheme,[validity_period],service_center_address,service_center_address_type,sms_message_body_length]<CR><LF>sms_message_body
						// fields := strings.Split(strings.TrimSpace(infos[1]), ",")
						bodyres := <-m.recvedChan
						var msgoct []byte
						if msgoct, err = hex.DecodeString(bodyres.Line); err != nil {
							fmt.Printf("解码短信内容出错: %v", err)
						} else {
							msg := &sms.Message{}
							if _, err = msg.ReadFrom(msgoct); err != nil {
								fmt.Printf("解码短信PDU出错: %v", err)
							} else {
								m.Message <- msg
							}
						}
					} else {
						m.printf("错误的CMGR命令: %s", response.Line)
					}
				case "+CMGL":
					if len(infos) == 2 {
						//<index>,<stat>,<oa>,[<alpha>],[<scts>]<CR><LF><data><CR><LF>
						fields := strings.Split(strings.TrimSpace(infos[1]), ",")
						bodyres := <-m.recvedChan
						var index uint64
						var msgoct []byte
						if msgoct, err = hex.DecodeString(bodyres.Line); err != nil {
							fmt.Printf("解码短信内容出错: %v", err)
						} else if index, err = strconv.ParseUint(fields[0], 10, 16); err != nil {
							fmt.Printf("解码短信Index出错: %v", err)
						} else {
							msg := &sms.Message{}
							if _, err = msg.ReadFrom(msgoct); err != nil {
								fmt.Printf("解码短信PDU出错: %v", err)
							} else {
								m.Message <- msg
							}
							go func() {
								if err = m.CMGD(index, DelIndex); err != nil {
									fmt.Printf("删除短信出错: %v", err)
								}
							}()
						}
					} else {
						m.printf("错误的CMGL命令: %s", response.Line)
					}
				default:
					if len(infos) == 1 {
						reply.WriteString(strings.TrimSpace(infos[0]))
						reply.WriteString(Sep)
					} else {
						m.printf("未知命令: %s", infos[0])
					}
					// case "CONNECT": // "Connect":
					// case "RING": // "Ringing":
					// case "BUSY": // "Busy":
					// case "NO CARRIER": // "No carrier":
					// case "NO DIALTONE": // "No dialtone":
					// case "NO ANSWER": // "No answer":
					// case "COMMAND NOT SUPPORT": // "Command is not supported":
					// case "TOO MANY PARAMETERS": // "Too many parameters":
					// case "SM BL READY": // "SM BL Ready":
					// case "CALL READY": // "SIM card has ready":
					// case "SIM CARD HAVE INSERT": // "SIM Card have insert":
				}
			}

		}
	}
}

// BOOT sends AT^BOOT with the given token to the device. This completes
// the handshaking procedure.
func (m *Modem) BOOT(token uint64) error {
	req := fmt.Sprintf(`AT^BOOT=%d,0`, token)
	_, err := m.sendWait(req)
	return err
}

// ATZ sends ATZ reset modem
func (m *Modem) ATZ() error {
	_, err := m.sendWait(`ATZ`)
	return err
}

// ATE sends ATE set show back
func (m *Modem) ATE(open bool) error {
	var req string
	if open {
		req = "ATE1"
	} else {
		req = "ATE0"
	}
	_, err := m.sendWait(req)
	return err
}

// CUSD sends AT+CUSD with the given parameters to the device. This will invoke an USSD request.
func (m *Modem) CUSD(reporting USSDType, octets []byte, enc Encoding) error {
	req := fmt.Sprintf(`AT+CUSD=%d,%02X,%d`, reporting, octets, enc)
	_, err := m.sendWait(req)
	return err
}

// CMGR sends AT+CMGR with the given index to the device and returns the message contents.
func (m *Modem) CMGR(index uint64) error {
	req := fmt.Sprintf(`AT+CMGR=%d`, index)
	_, err := m.sendWait(req)
	return err
}

// CMGD sends AT+CMGD with the given index and option to the device. Option defines the mode
// in which messages will be deleted. The default mode is to delete by index.
func (m *Modem) CMGD(index uint64, option DeleteOption) error {
	req := fmt.Sprintf(`AT+CMGD=%d,%d`, index, option)
	_, err := m.sendWait(req)
	return err
}

// CPIN sends AT+CPIN? with the given options to the device. It check sim chard is
// ready for use
func (m *Modem) CPIN() error {
	_, err := m.sendWait(`AT+CPIN?`)
	return err
}

// CPMS sends AT+CPMS with the given options to the device. It allows to select
// the storage type for different kinds of messages and message notifications.
func (m *Modem) CPMS(mems ...MemoryType) error {
	var req string
	switch len(mems) {
	case 1:
		req = fmt.Sprintf(`AT+CPMS="%s"`, mems[0])
	case 2:
		req = fmt.Sprintf(`AT+CPMS="%s","%s"`, mems[0], mems[1])
	case 3:
		req = fmt.Sprintf(`AT+CPMS="%s","%s","%s"`, mems[0], mems[1], mems[2])
	default:
		return errors.New("Unhandled len of memorys")
	}
	_, err := m.sendWait(req)
	return err
}

// CREG sends AT+CREG?
// It's used to check network reged
func (m *Modem) CREG() error {
	_, err := m.sendWait(`AT+CREG?`)
	return err
}

// CNMI sends AT+CNMI with the given parameters to the device.
// It's used to adjust the settings of the new message arrival notifications.
/*
	＜mode＞控制通知TE的方式。
    0——先将通知缓存起来，再按照＜mt＞的值进行发送。
    1——在数据线空闲的情况下，通知TE，否则，不通知TE。
    2——数据线空闲时，直接通知TE；否则先将通知缓存起来，待数据线空闲时再行发送。
	3——直接通知TE。在数据线被占用的情况下，通知TE的消息将混合在数据中一起传输。

	＜mt＞设置短消息存储和通知TE的内容。
    0——接受的短消息存储到默认的内存位置（包括class 3），不通知TE。
    1——接收的短消息储存到默认的内存位置，并且向TE发出通知（包括class 3）。通知的形式为：
     ＋CMTI：”SM”，＜index＞
    2——对于class 2短消息，储存到SIM卡，并且向TE发出通知；对于其他class，直接将短消息转发到TE：
     ＋CMT：[＜alpha＞]，＜length＞＜CR＞＜LF＞＜pdu＞（PDU模式）
     或者＋CMT：＜oa＞，[＜alpha＞，]＜scts＞[，＜tooa＞，＜fo＞，＜pid＞，＜dcs＞，＜sca＞，＜tosca＞，＜length＞]＜CR＞＜LF＞＜data＞（text模式）
	3——对于class 3短消息，直接转发到TE，同＜mt＞＝2；对于其他class，同＜mt＞＝1。

	＜bm＞设置小区广播
    0——小区广播不通知
    2——新的小区广播通知，返回
    +CBM:;length;;CR;;LF;;pdu;
	3——Class3格式的小区广播通知，使用bm=2格式

	＜ds＞状态报告
    0——状态报告不通知
    1——新的状态报告通知，返回：
    +CDS:;length;;CR;;LF;;pdu;
    2——如果新的状态报告存储到ME，则返回：
	+CDSI:;mem;,;index;

	＜brf＞
    1——始终为1
*/
func (m *Modem) CNMI(mode, mt, bm, ds, bfr int) error {
	req := fmt.Sprintf(`AT+CNMI=%d,%d,%d,%d,%d`, mode, mt, bm, ds, bfr)
	_, err := m.sendWait(req)
	return err
}

// CMGF sends AT+CMGF with the given value to the device. It toggles
// the mode of message handling betwen PDU and TEXT.
//
// Note, that the at package works only in PDU mode.
func (m *Modem) CMGF(text bool) error {
	var flag int
	if text {
		flag = 1
	}
	req := fmt.Sprintf(`AT+CMGF=%d`, flag)
	_, err := m.sendWait(req)
	return err
}

// CSMP In text mode there are some additional parameters that can be set
// text mode: 17,167,0,16
// unicode  : 1,167,0,8
func (m *Modem) CSMP(a, b, c, d int) error {
	req := fmt.Sprintf(`AT+CSMP=%d,%d,%d,%d`, a, b, c, d)
	_, err := m.sendWait(req)
	return err
}

// CSCA sms center
func (m *Modem) CSCA(smsc string) error {
	var req string
	if smsc == "" {
		req = `AT+CSCA?`
	} else if strings.HasPrefix(smsc, "+") {
		req = fmt.Sprintf(`AT+CSCA="%s",145`, smsc)
	} else {
		req = fmt.Sprintf(`AT+CSCA="%s",129`, smsc)
	}
	_, err := m.sendWait(req)
	return err
}

// CSCS ("GSM","HEX","IRA","PCCP437","UCS2","8859-1")
func (m *Modem) CSCS(encode string) error {
	req := fmt.Sprintf(`AT+CSCS="%s"`, encode)
	_, err := m.sendWait(req)
	return err
}

// CMGL sends AT+CMGL with the given filtering flag to the device and then parses
// the list of received messages that match ther filter. See MessageFlags for the
// list of supported filters.
func (m *Modem) CMGL(flag MessageFlag) error {
	var req string
	if !m.isCDMA() {
		req = fmt.Sprintf(`AT+CMGL=%d`, flag)
	} else {
		req = fmt.Sprintf(`AT^HCMGL=%d`, flag)
	}
	_, err := m.sendWait(req)
	return err
}

// CMGSPDU sends AT+CMGS with the given parameters to the device. This is used to send SMS
// using the given PDU data. Length is a number of TPDU bytes.
func (m *Modem) CMGSPDU(length int, octets []byte) error {
	var command string
	if !m.isCDMA() {
		command = fmt.Sprintf("AT+CMGS=%d", length)
	} else {
		command = fmt.Sprintf("AT^HCMGS=%d", length)
	}
	err := m.sendInteractive(command, hex.EncodeToString(octets))
	return err
}

// CMGSTEXT sends AT+CMGS with the given parameters to the device. This is used to send SMS
// using the given text data.
func (m *Modem) CMGSTEXT(mobile, text string) error {
	err := m.sendInteractive(fmt.Sprintf(`AT+CMGS="%s"`, mobile), text)
	return err
}

// SYSCFG sends AT^SYSCFG with the given parameters to the device.
// The arguments of this command may vary, so the options are limited to switchng roaming and
// cellular mode on/off.
func (m *Modem) SYSCFG(roaming, cellular bool) error {
	var roam int
	if roaming {
		roam = 1
	}
	var cell int
	if cellular {
		cell = 2
	} else {
		cell = 1
	}
	req := fmt.Sprintf(`AT^SYSCFG=2,2,3FFFFFFF,%d,%d`, roam, cell)
	_, err := m.sendWait(req)
	return err
}

// SYSINFO sends AT^SYSINFO to the device and parses the output.
func (m *Modem) SYSINFO() error {
	_, err := m.sendWait(`AT^SYSINFO`)
	return err
}

// COPS sends AT+COPS to the device with parameters that define autosearch and
// the operator's name representation. The default represenation is numerical.
func (m *Modem) COPS(auto bool, text bool) error {
	var a, t int
	if !auto {
		a = 1
	}
	if !text {
		t = 2
	}
	req := fmt.Sprintf(`AT+COPS=%d,%d`, a, t)
	_, err := m.sendWait(req)
	return err
}

// OperatorName sends AT+COPS? to the device and gets the operator's name.
func (m *Modem) OperatorName() error {
	_, err := m.sendWait(`AT+COPS?`)
	return err
}

// ModelName sends AT+GMM to the device and gets the modem's model name.
func (m *Modem) ModelName() error {
	reply, err := m.sendWait(`AT+GMM`)
	if err == nil {
		m.State.ModelName = reply
	}
	return err
}

// IMEI sends AT+GSN to the device and gets the modem's IMEI code.
func (m *Modem) IMEI(imei string) error {
	//可 GSN 可 CGSN
	if imei == "" {
		_, err := m.sendWait(`AT+CGSN`)
		return err
	}
	_, err := m.sendWait(fmt.Sprintf(`AT+IMEI=1,%s`, imei))
	return err
}

// MEID sends AT^MEID to the device and gets the modem's MEID code.
func (m *Modem) MEID() error {
	_, err := m.sendWait(`AT^MEID`)
	return err
}

// IMSI sends AT+CIMI to the device and gets the modem's IMSI code.
func (m *Modem) IMSI() error {
	reply, err := m.sendWait(`AT+CIMI`)
	if err == nil {
		m.LRCIMI = strings.TrimSpace(reply)
	}
	return err
}

// Init invokes a set of methods that will make the initial setup of the modem.
func (m *Modem) Init() error {
	var err error
	if _, err = m.sendWait(`AT`); err != nil { // kinda flush
		if err == ErrTimeout {
			m.connection.Write([]byte(Sub))
		}
		return errors.New("modem init faild")
	}
	// if send atz some modem will be need sms center address
	// if err = p.ATZ(); err != nil {
	// 	return errors.New("unable to reset modem")
	// }
	if err = m.ATE(false); err != nil {
		m.printf("unable to reset modem")
	}
	// if err = p.COPS(true, true); err != nil {
	// 	return errors.New("unable to adjust the format of operator's name")
	// }
	if err = m.SYSINFO(); err != nil {
		m.State = &DeviceState{
			SystemMode: MGsmWcdma,
		}
	}
	// if p.dev.State.OperatorName, err = p.OperatorName(); err != nil {
	// 	p.dev.State.OperatorName = "unknow"
	// 	//return errors.New("unable to read operator's name")
	// }
	if err = m.ModelName(); err != nil {
		m.printf("unable to read modem's model name[%v]", err)
	}
	if m.isCDMA() {
		if err = m.MEID(); err != nil {
			m.State.MEID = "unknow"
		}
	} else {
		if err = m.IMEI(""); err != nil {
			m.State.IMEI = "unknow"
		}
	}
	return nil
}

// Initialize init sim card?
func (m *Modem) Initialize(text bool) (err error) {
	//MemoryTypes.NvRAM, MemoryTypes.NvRAM, MemoryTypes.NvRAM
	if err = m.CPMS(MTSim, MTSim, MTSim); err != nil {
		//return fmt.Errorf("unable to set messages storage[%v]", err)
	}
	// if err = p.CNMI(0, 0, 0, 0, 1); err != nil {
	// 	return fmt.Errorf("unable to turn on message notifications[%v]", err)
	// }
	// p.dev.Notifycation = false
	if err = m.CNMI(2, 1, 0, 2, 1); err != nil {
		if err = m.CNMI(0, 0, 0, 0, 1); err != nil {
			return fmt.Errorf("unable to turn on message notifications[%v]", err)
		}
		m.Notifycation = false
	} else {
		m.Notifycation = true
	}
	if err = m.CMGF(text); err != nil {
		return fmt.Errorf("unable to switch message format to PDU or Text[%v]", err)
	}
	return nil
}

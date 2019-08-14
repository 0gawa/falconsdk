package falconsdk

import (
    "fmt"
    "time"
    "strconv"
    "io/ioutil"
    "bufio"
    "net/http"
    "encoding/json"
)

type UnixEpoch interface {
    Time() time.Time
}

type UnixEpochMilliSec int64

func (millisec UnixEpochMilliSec) Time() time.Time {
    sec := int64(millisec / 1000)
    milli := int64(millisec % 1000)
    return time.Unix(sec, milli * 1000)
}

type EventMetadata struct {
    CustomerIDString string `json:"customerIDString"`
    Offset int64 `json:"offset"`
    EventType string `json:"eventType"`
    EventCreationTime UnixEpochMilliSec `json:"eventCreationTime"`
    Version string `json:"version"`
}

type StreamEvent struct {
    Metadata EventMetadata `json:"metadata"`
    Event interface{} `json:"event"`
}

type AuthActivityAuditEvent struct {
    UserId string `json:"UserId"`
    UserIp string `json:"UserIp"`
    OperationName string `json:"OperationName"`
    ServiceName string `json:"ServiceName"`
    Success bool `json:"Success"`
    UTCTimestamp int64 `json:"UTCTimestamp"`
    AuditKeyValues []struct {
        Key string `json:"Key"`
        ValueString string `json:"ValueString"`
    } `json:"AuditKeyValues"`
}

type UserActivityAuditEvent struct {
    UserId string `json:"UserId"`
    UserIp string `json:"UserIp"`
    OperationName string `json:"OperationName"`
    ServiceName string `json:"ServiceName"`
    UTCTimestamp int64 `json:"UTCTimestamp"`
    AuditKeyValues []struct {
        Key string `json:"Key"`
        ValueString string `json:"ValueString"`
    } `json:"AuditKeyValues"`
}

type RemoteResponseSessionStartEvent struct {
    SessionId string `json:"SessionId"`
    HostnameField string `json:"HostnameField"`
    UserName string `json:"UserName"`
    StartTimestamp int64 `json:"StartTimestamp"`
}

type RemoteResponseSessionEndEvent struct {
    SessionId string `json:"SessionId"`
    HostnameField string `json:"HostnameField"`
    UserName string `json:"UserName"`
    EndTimestamp int64 `json:"EndTimestamp"`
    Commands []string `json:"Commands"`
}

type DetectionSummaryEvent struct {
    ProcessStartTime int64 `json:"ProcessStartTime"`
    ProcessEndTime int64 `json:"ProcessEndTime"`
    ProcessId int64 `json:"ProcessId"`
    ParentProcessId int64 `json:"ParentProcessId"`
    Severity int `json:"Severity"`
    SeverityName string `json:"SeverityName"`
    DetectDescription string `json:"DetectDescription"`
    DetectName string `json:"DetectName"`
    DetectId string `json:"DetectId"`
    Tactic string `json:"Tactic"`
    Technique string `json:"Technique"`
    Objective string `json:"Objective"`
    FileName string `json:"FileName"`
    FilePath string `json:"FilePath"`
    IOCType string `json:"IOCType"`
    IOCValue string `json:"IOCValue"`
    SHA256String string `json:"SHA256String"`
    MD5String string `json:"MD5String"`
    CommandLine string `json:"CommandLine"`
    ParentImageFileName string `json:"ParentImageFileName"`
    ParentCommandLine string `json:"ParentCommandLine"`
    GrandparentImageFileName string `json:"GrandparentImageFileName"`
    GrandparentCommandLine string `json:"GrandparentCommandLine"`
    ComputerName string `json:"ComputerName"`
    LocalIP string `json:"LocalIP"`
    MACAddress string `json:"MACAddress"`
    UserName string `json:"UserName"`
    SensorId string `json:"SensorId"`
    PatternDispositionDescription string `json:"PatternDispositionDescription"`
    PatternDispositionValue int `json:"PatternDispositionValue"`
    PatternDispositionFlags struct {
        Indicator bool `json:"Indicator"`
	Detect bool `json:"Detect"`
	InddetMask bool `json:"InddetMask"`
	SensorOnly bool `json:"SensorOnly"`
	Rooting bool `json:"Rooting"`
	KillProcess bool `json:"KillProcess"`
	KillSubProcess bool `json:"KillSubProcess"`
	QuarantineMachine bool `json:"QuarantineMachine"`
	QuarantineFile bool `json:"QuarantineFile"`
	PolicyDisabled bool `json:"PolicyDisabled"`
	KillParent bool `json:"KillParent"`
	OperationBlocked bool `json:"OperationBlocked"`
	ProcessBlocked bool `json:"ProcessBlocked"`
    } `json:"PatternDispositionFlags"`
    DnsRequests []struct {
        DomainName string `json:"DomainName"`
	RequestType string `json:"RequestType"`
	LoadTime int64 `json:"LoadTime"`
	InterfaceIndex int `json:"InterfaceIndex"`
	CausedDetect bool `json:"CausedDetect"`
    } `json:"DnsRequests"`
    NetworkAccesses []struct {
        AccessType int `json:"AccessType"`
	AccessTimestamp int64 `json:"AccessTimestamp"`
	Protocol string `json:"Protocol"`
	LocalAddress string `json:"LocalAddress"`
	LocalPort int `json:"LocalPort"`
	RemoteAddress string `json:"RemoteAddress"`
	RemotePort int `json:"RemotePort"`
	ConnectionDirection int `json:"ConnectionDirection"`
	IsIPV6 bool `json:"IsIPV6"`
    } `json:"NetworkAccesses"`
    DocumentsAccessed []struct {
        Timestamp int64 `json:"Timestamp"`
	FileName string `json:"FileName"`
	FilePath string `json:"FilePath"`
    } `json:"DocumentsAccessed"`
    ExecutablesWritten []struct {
        Timestamp int64 `json:"Timestamp"`
	FileName string `json:"FileName"`
	FilePath string `json:"Filepath"`
    } `json:"ExecutablesWritten"`
    ScanResults []struct {
        Engine string `json:"Engine"`
	ResultName string `json:"ResultName"`
	Version string `json:"Version"`
	Detected bool `json:"Detected"`
    } `json:"ScanResults"`
    FalconHostLink string `json:"FalconHostLink"`
}

func (e *StreamEvent) UnmarshalJSON(data []byte) error {
    type Alias StreamEvent
    alias := &struct {
        Event json.RawMessage `json:"event"`
	*Alias
    }{
        Alias: (*Alias)(e),
    }

    if err := json.Unmarshal(data, &alias); err != nil {
        return err
    }
    switch e.Metadata.EventType {
    case "AuthActivityAuditEvent":
        var authEvent AuthActivityAuditEvent
	    if err := json.Unmarshal(alias.Event, &authEvent); err != nil {
            return err
	    }
	    e.Event = &authEvent
    case "UserActivityAuditEvent":
        var userAuditEvent UserActivityAuditEvent
	    if err := json.Unmarshal(alias.Event, &userAuditEvent); err != nil {
            return err
	    }
	    e.Event = &userAuditEvent
    case "DetectionSummaryEvent":
        var detectSummary DetectionSummaryEvent
	    if err := json.Unmarshal(alias.Event, &detectSummary); err != nil {
            return err
	    }
	    e.Event = &detectSummary
    case "RemoteResponseSessionStartEvent":
        var rtrStartEvent RemoteResponseSessionStartEvent
        if err := json.Unmarshal(alias.Event, &rtrStartEvent); err != nil {
            return err
        }
        e.Event = &rtrStartEvent
    case "RemoteResponseSessionEndEvent":
        var rtrEndEvent RemoteResponseSessionEndEvent
        if err := json.Unmarshal(alias.Event, &rtrEndEvent); err != nil {
            return err
        }
        e.Event = &rtrEndEvent
    }
    return nil
}

type EventSubscriber func(event *StreamEvent)

type discoverStreamResult struct {
    Errors []struct {
        Code int32 `json:"code"`
        Id string `json:"id"`
        Message string `json:"message"`
    } `json:"errors"`
    Meta struct {
        Pagination struct {
            Limit int64 `json:"limit"`
            Offset int64 `json:"offset"`
            Total int64 `json:"total"`
        } `json:"pagination"`
    } `json:"meta"`
    Resources []struct {
        DataFeedURL string `json:"dataFeedURL"`
        RefreshActiveSessionInterval int64 `json:"refreshActiveSessionInterval"`
        RefreshActiveSessionURL string `json:"refreshActiveSessionURL"`
        SessionToken struct {
            Expiration string `json:"expiration"`
            Token string `json:"token"`
        } `json:"sessionToken"`
    } `json:"resources"`
}

func (client clientImpl) discoverStream(appId string) *discoverStreamResult {
    httpClient := &http.Client{}
    req, err := http.NewRequest("GET", fmt.Sprintf("%s%s", apiBaseUrl, discoverStreamUrl), nil)
    if err != nil {
        panic(err)
    }
    query := req.URL.Query()
    accessToken := client.getAccessToken()
    query.Add("appId", appId)
    req.URL.RawQuery = query.Encode()
    req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
    req.Header.Add("Accept", "application/json")

    res, err := httpClient.Do(req)
    if err != nil {
        panic(err)
    }
    defer res.Body.Close()
    rawString, err := ioutil.ReadAll(res.Body)
    if err != nil {
        panic(err)
    }
    var result discoverStreamResult
    if err := json.Unmarshal(rawString, &result); err != nil {
        panic(err)
    }
    return &result
}

func (client *clientImpl) StartStreaming(appId string, offset int64, callback EventSubscriber) {
    discoverResult := client.discoverStream(appId)
    for _, streamInfo := range discoverResult.Resources {
        url := streamInfo.DataFeedURL
        token := streamInfo.SessionToken.Token

        ch := make(chan *StreamEvent)
        go func() {
            httpClient := &http.Client{}
            req, err := http.NewRequest("GET", url, nil)
            if err != nil {
                panic(err)
            }
            if offset > 0 {
                q := req.URL.Query()
                q.Add("offset", strconv.FormatInt(offset,10))
                req.URL.RawQuery = q.Encode()
            }
            req.Header.Add("Authorization", fmt.Sprintf("Token %s", token))
            req.Header.Add("Accept", "application/json")
            req.Header.Add("Connection", "keep-alive")
            res, err := httpClient.Do(req)
            if err != nil {
                panic(err)
            }
            defer res.Body.Close()
            scanner := bufio.NewScanner(res.Body)
            for {
                if scanner.Scan() {
                    text := scanner.Text()
                    if len(text) > 0 {
                        var streamEvent StreamEvent
                        if err := json.Unmarshal([]byte(text), &streamEvent); err != nil {
                            panic(err)
                        }
                        ch <- &streamEvent
                    }
                }
            }
        }()
        go func() {
            for event := range ch {
                callback(event)
            }
        }()

        refreshUrl := streamInfo.RefreshActiveSessionURL
        interval := time.Duration(streamInfo.RefreshActiveSessionInterval - 5 * 60) * time.Second
        ticker := time.NewTicker(interval)
        go func() {
            for {
                <- ticker.C
                httpClient := &http.Client{}
                req, err := http.NewRequest("POST", refreshUrl, nil)
                if err != nil {
                    panic(err)
                }
                bearerToken := client.getAccessToken()
                req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", bearerToken))
                req.Header.Add("Accept", "application/json")
                req.Header.Add("Content-Type", "application/json")
                res, err := httpClient.Do(req)
                if err != nil {
                    panic(err)
                }
                res.Body.Close()
            }
        }()
    }
}

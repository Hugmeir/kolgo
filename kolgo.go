package kolgo
import (
    "os"
    "sync"
    "regexp"
    "fmt"
    "time"
    "strconv"
    "net/url"
    "net/http"
    "net/http/cookiejar"
    "io/ioutil"
    "bytes"
    "strings"
    "errors"
    "encoding/json"
    "compress/gzip"
)

const baseUrl          = "https://www.kingdomofloathing.com/"
const (
    loginUrl         = baseUrl + "login.php"
    logoutUrl        = baseUrl + "logout.php"
    newMessageUrl    = baseUrl + "newchatmessages.php"
    submitMessageUrl = baseUrl + "submitnewchat.php"
    lChatUrl         = baseUrl + "lchat.php"
    uneffectUrl      = baseUrl + "uneffect.php"
    invUseUrl        = baseUrl + "inv_use.php"
    invSpleenUrl     = baseUrl + "inv_spleen.php"
    multiuseUrl      = baseUrl + "multiuse.php"
    clanHallUrl      = baseUrl + "clan_hall.php"
)

type MsgType int
const (
    Command MsgType = iota
    Message
)

type MessageToKoL struct {
    Destination string
    Message     string
    Time        time.Time
    Type        MsgType
}

type handlerInterface func(KoLRelay, ChatMessage)
type KoLRelay interface {
    LogIn(string)              error
    LogOut()                   ([]byte, error)
    StartChatPoll(string)
    StartMessagePoll(string)
    HandleKoLException(error, string)  error
    AddHandler(int, handlerInterface)
    SendMessage(string, string)
    SendCommand(string, string)


    // Not-so-public interface:
    SubmitChat(string, string) ([]byte, error)
    PollChat()                 ([]byte, error)
    ClanHall()                 ([]byte, error)
    InvUse(string, int)        ([]byte, error)
    InvSpleen(string)          ([]byte, error)
    Uneffect(string)           ([]byte, error)
    DecodeChat([]byte)         (*ChatResponse, error)
    SenderIdFromMessage(ChatMessage) string

    ResetAwayTicker()

    PlayerId() string

}

const (
    Public  = iota
    Private
    Event
    System
)
func (kol *relay) AddHandler(eventType int, cb handlerInterface) {
    handlers, ok := kol.handlers.Load(eventType)
    if ok {
        kol.handlers.Store(eventType, append(handlers.([]handlerInterface), cb))
    } else {
        kol.handlers.Store(eventType, []handlerInterface{cb})
    }
}

func (kol *relay) SendCommand(d string, m string ) {
    now := time.Now()
    msg := &MessageToKoL{ d, m, now, Command }
    kol.MessagesC <- msg
}

func (kol *relay) SendMessage(d string, m string ) {
    now := time.Now()
    msg := &MessageToKoL{ d, m, now, Message }
    kol.MessagesC <- msg
}

type relay struct {
    UserName      string
    HttpClient    *http.Client
    SessionId     string
    PasswordHash  string
    LastSeen      string
    playerId      string

    Log           *os.File
    handlers      sync.Map

    AwayTicker    *time.Ticker
    MessagesC     chan *MessageToKoL
}

func NewKoL(userName string, f *os.File) KoLRelay {
    cookieJar, _ := cookiejar.New(nil)
    httpClient    := &http.Client{
        Jar:           cookieJar,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            // KoL sends the session ID Set-Cookie on a 301, so we need to
            // check all redirects for cookies.
            // This looks like a golang bug, in that the cookiejar is not
            // being updated during redirects.
            cookies := cookieJar.Cookies(req.URL)
            for i := 0; i < len(cookies); i++ {
                req.Header.Set( cookies[i].Name, cookies[i].Value )
            }
            return nil
        },
    }

    kol := &relay{
        UserName:   userName,
        HttpClient: httpClient,
        LastSeen:   "0",
        playerId:   "3152049", // TODO
        AwayTicker: time.NewTicker(3*time.Minute),
        PasswordHash: "",

        MessagesC: make(chan *MessageToKoL, 200),
        Log: f,
    }

    return kol
}

func (kol *relay)PlayerId() string {
    return kol.playerId
}

func (kol *relay) LogIn(password string) error {
    httpClient := kol.HttpClient

    loginParams := url.Values{}
    loginParams.Set("loggingin",    "Yup.")
    loginParams.Set("loginname",    kol.UserName)
    loginParams.Set("password",     password)
    loginParams.Set("secure",       "0")
    loginParams.Set("submitbutton", "Log In")

    loginBody := strings.NewReader(loginParams.Encode())
    req, err := http.NewRequest("POST", loginUrl, loginBody)
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    resp, err := httpClient.Do(req)

    if err != nil {
        return err
    }
    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)
    for _, cookie := range httpClient.Jar.Cookies(req.URL) {
        if strings.EqualFold(cookie.Name, "PHPSESSID") {
            kol.SessionId = cookie.Value
        }
    }

    if kol.SessionId == "" {
        return errors.New("Failed to aquire session id")
    }

    responseErr := CheckResponseForErrors(resp, body)
    if responseErr != nil {
        return responseErr
    }

    // Looks like we logged in successfuly.  Try to get the pwd hash
    // and player ID
    err = kol.ResolveCharacterData()
    if err != nil {
        return err
    }

    return nil
}

func (kol *relay)SenderIdFromMessage(message ChatMessage) string {
    sender := message.Who
    var senderId string
    switch sender.Id.(type) {
        case string:
            senderId, _ = sender.Id.(string)
        case int64:
            senderId = strconv.FormatInt(sender.Id.(int64), 10)
        case float64:
            senderId = strconv.FormatInt(int64(sender.Id.(float64)), 10)
    }
    return senderId
}

func MessageTypeFromMessage(message ChatMessage) int {
    if message.Type == "private" {
        return Private
    } else if message.Type == "event" {
        return Event
    } else if message.Type == "public" {
        return Public
    } else if message.Type == "system" {
        return System
    } else {
        return -1
    }
}

func (kol *relay)StartMessagePoll(password string) {
    // Set up some super conservative rate limiting:
    throttle := time.Tick( 1 * time.Second )
    for { // just an infinite loop
        // select waits until ticker ticks over, then runs this code
        select {
            case msg := <-kol.MessagesC:
                elapsed := time.Now().Sub(msg.Time).Seconds()
                if elapsed > 30 {
                    // Stop relaying old messages.
                    continue
                }
                // First, disarm the away ticker:
                if msg.Type != Command {
                    // Make sure we aren't massively spamming the game:
                    <-throttle
                }

                // Actually send the message to the game:
                _, err := kol.SubmitChat(msg.Destination, msg.Message)
                if err == nil {
                    continue
                }

                // Got an error!
                fatalError := kol.HandleKoLException(err, password)
                if fatalError != nil {
                    fmt.Println("Got an error submitting to kol?!")
                    panic(fatalError)
                }

                // Exception was handled, so retry:
                _, err = kol.SubmitChat(msg.Destination, msg.Message)
                if err != nil {
                    kolError, ok := err.(*KoLError)
                    if !ok {
                        // Well, we tried, silver star.  Die:
                        panic(err)
                    }
                    if kolError.ErrorType == BadRequest || kolError.ErrorType == ServerError {
                        // Eh, it was logged, just drop it
                        continue
                    }
                    panic(err)
                }
            case <-kol.AwayTicker.C:
                _, err := kol.SubmitChat("/who", "clan")
                fatalError := kol.HandleKoLException(err, password)
                if fatalError != nil {
                    panic(fatalError)
                }
        }
    }
}

func (kol *relay)StartChatPoll(password string) {

    // Poll every 3 seconds:
    pollDelay := 3 * time.Second
    ticker := time.NewTicker(pollDelay)
    defer ticker.Stop()

    for { // just an infinite loop
        // select waits until ticker ticks over, then runs this code
        select {
        case <-ticker.C:
            if kol.PasswordHash == "" {
                continue
            }
            rawChatReponse, err := kol.PollChat()
            if err != nil {
                fatalError      := kol.HandleKoLException(err, password)
                if fatalError != nil {
                    // Probably rollover?
                    panic(fatalError)
                }
                fmt.Println("Polling KoL had some error we are now ignoring: ", err)
                continue
            }

            // Dumb heuristics!  If it contains msgs:[], it's an empty response,
            // so don't log it... unless it also contains "output":, in which case
            // there might be an error in there somewhere.
            chatReponseString := string(rawChatReponse)
            if !strings.Contains(chatReponseString, `"msgs":[]`) || strings.Contains(chatReponseString, `"output":`) {
                fmt.Fprintf(kol.Log, "%s: %s\n", time.Now().Format(time.RFC3339), string(rawChatReponse))
            }

            chatResponses, err := kol.DecodeChat(rawChatReponse)
            if err != nil {
                fmt.Println("Could not decode chat from KoL, ignoring it for now ", err)
                continue
            }

            newDelay := pollDelay
            switch chatResponses.Delay.(type) {
                case string:
                    i, _ := strconv.Atoi(chatResponses.Delay.(string))
                    newDelay = time.Duration(i) * time.Millisecond
                case int:
                    newDelay    = time.Duration(chatResponses.Delay.(int)) * time.Millisecond
                case int64:
                    newDelay    = time.Duration(chatResponses.Delay.(int64)) * time.Millisecond
                case float64:
                    newDelay    = time.Duration(chatResponses.Delay.(float64)) * time.Millisecond
            }

            if newDelay != pollDelay && newDelay < 10 && newDelay >= 2 {
                fmt.Println("Changed the polling interval to ", newDelay)
                pollDelay = newDelay
                ticker.Stop()
                ticker = time.NewTicker(pollDelay)
            }

            if chatResponses.Msgs != nil && len(chatResponses.Msgs) > 0 {
                go InvokeChatResponseHandlers(kol, chatResponses)
            }
        }
    }
}

func InvokeChatResponseHandlers(kol *relay, chatResponses *ChatResponse) {
    for _, message := range chatResponses.Msgs {
        senderId := kol.SenderIdFromMessage(message)
        if senderId == kol.PlayerId() {
            continue
        }

        t := MessageTypeFromMessage(message)
        handlers, ok := kol.handlers.Load(t)
        if !ok {
            continue
        }
        for _, cb := range handlers.([]handlerInterface) {
            cb(kol, message)
        }
    }
}

func (kol *relay)ClanHall() ([]byte, error) {
    httpClient := kol.HttpClient
    req, err := http.NewRequest("GET", clanHallUrl, nil)
    if err != nil {
        return nil, err
    }

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)
    return body, CheckResponseForErrors(resp, body)
}

func (kol *relay) LogOut() ([]byte, error) {
    defer kol.AwayTicker.Stop()

    httpClient := kol.HttpClient
    req, err := http.NewRequest("GET", logoutUrl, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Accept",          "application/json, text/javascript, */*; q=0.01")
    req.Header.Set("Accept-Encoding", "gzip")
    req.Header.Set("Refered",         "https://www.kingdomofloathing.com/mchat.php")

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)
    return body, CheckResponseForErrors(resp, body)
}

// {"msgs":[],"last":"1468191607","delay":3000}
// {"msgs":[{"msg":"Howdy.","type":"public","mid":"1468191682","who":{"name":"Soloflex","id":"2886007","color":"black"},"format":"0","channel":"clan","channelcolor":"green","time":"1537040363"}],"last":"1468191682","delay":3000}
type KoLPlayer struct {
    Name  string `json:"name"`
    Id    interface{} `json:"id"`
    Color string `json:"color"`
}
type ChatMessage struct {
    Msg          string    `json:"msg"`
    Type         string    `json:"type"`
    Mid          interface{}    `json:"mid"`
    Who          KoLPlayer `json:"who"`
    Format       interface{}    `json:"format"`
    Channel      string    `json:"channel"`
    ChannelColor string    `json:"channelcolor"`
    Time         interface{}    `json:"time"`
    Link         interface{}    `json:"link"` // usually missing, sometimes false (bool), sometimes a string ("clan_hall.php")
}
type ChatResponse struct {
    Msgs  []ChatMessage  `json:"msgs"`
    Last  interface{}    `json:"last"`
    Delay interface{}    `json:"delay"`
}

func (kol *relay) PollChat() ([]byte, error) {
    httpClient := kol.HttpClient
    req, err := http.NewRequest("GET", fmt.Sprintf("%s?lasttime=%s&j=1", newMessageUrl, kol.LastSeen), nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Accept",          "application/json, text/javascript, */*; q=0.01")
    req.Header.Set("Accept-Encoding", "gzip")
    req.Header.Set("Refered",         "https://www.kingdomofloathing.com/mchat.php")

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)

    if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
        gr, err := gzip.NewReader(bytes.NewBuffer(body))
        defer gr.Close()
        body, err = ioutil.ReadAll(gr)
        if err != nil {
            return nil, err
        }
    }

    return body, CheckResponseForErrors(resp, body)
}

func (kol *relay)DecodeChat(jsonChat []byte) (*ChatResponse, error) {
    var jsonResponse ChatResponse
    err := json.Unmarshal(jsonChat, &jsonResponse)
    if err != nil {
        fmt.Println("The body that broke us: ", string(jsonChat))
        return nil, err
    }

    switch jsonResponse.Last.(type) {
        case string:
            kol.LastSeen = jsonResponse.Last.(string)
        case float64:
            kol.LastSeen = fmt.Sprintf("%v", jsonResponse.Last)
    }

    return &jsonResponse, nil
}

const (
    Disconnect = iota
    Rollover
    BadRequest
    ServerError
    Unknown
)

type KoLError struct {
    ResponseBody []byte
    ErrorMsg     string
    ErrorType    int
}

func (error *KoLError) Error() string {
    return error.ErrorMsg
}

func (kol *relay)ResetAwayTicker() {
    if kol.AwayTicker != nil {
        kol.AwayTicker.Stop()
    }
    kol.AwayTicker = time.NewTicker(3*time.Minute)
}

func (kol *relay) SubmitChat(destination string, message string) ([]byte, error) {
    kol.ResetAwayTicker()

    httpClient  := kol.HttpClient
    msg         := destination + url.QueryEscape(" " + message)
    finalUrl   := fmt.Sprintf("%s?playerid=%s&pwd=%s&j=1&graf=%s", submitMessageUrl, kol.playerId, kol.PasswordHash, msg)
    req, err := http.NewRequest("POST", finalUrl, nil)
    if err != nil {
        return nil, err
    }

    //req.Header.Set("User-Agent",      "KoL-chat-to-Discord relay")
    req.Header.Set("X-Asym-Culprit",  "Maintained by Hugmeir(#3061055)")
    req.Header.Set("X-Asym-Reason",   "Uniting /clan and the clan Discord")
    req.Header.Set("X-Asym-Source",   "https://github.com/Hugmeir/kol-relay")
    req.Header.Set("Accept-Encoding", "gzip")
    req.Header.Set("Refered",         "https://www.kingdomofloathing.com/mchat.php")

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)

    if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
        gr, err := gzip.NewReader(bytes.NewBuffer(body))
        defer gr.Close()
        body, err = ioutil.ReadAll(gr)
        if err != nil {
            return nil, err
        }
    }

    if !strings.Contains(destination, "/who") {
        fmt.Fprintf(kol.Log, "%s %d [RESPONSE]: %s\n", time.Now().Format(time.RFC3339), os.Getpid(), string(body))
    }

    return body, CheckResponseForErrors(resp, body)
}

func CheckResponseForErrors(resp *http.Response, body []byte) error {
    if resp.StatusCode >= 400 && resp.StatusCode < 500 {
        return &KoLError {
            body,
            fmt.Sprintf("KoL returned a %d; our request was broken somehow", resp.StatusCode),
            BadRequest,
        }
    } else if resp.StatusCode >= 500 {
        return &KoLError {
            body,
            fmt.Sprintf("KoL returned a %d; game is broken!", resp.StatusCode),
            ServerError,
        }
    } else if resp.StatusCode >= 300 {
        return &KoLError {
            body,
            fmt.Sprintf("KoL returned a %d; redirect spiral?!", resp.StatusCode),
            ServerError,
        }
    }

    // So this was a 200.  Check where we ended up:
    finalURL := resp.Request.URL.String()
    if strings.Contains(finalURL, "login.php") {
        // Got redirected to login.php!  That means we were disconnected.
        return &KoLError{
            body,
            "Redirected to login.php when submiting a message, looks like we got disconnected",
            Disconnect,
        }
    } else if strings.Contains(finalURL, "maint.php") {
        return &KoLError{
            body,
            "Rollover",
            Rollover,
        }
    }

    return nil
}

/*GET inv_use.php?pwd=f4f8b4fa4058649c98df8676a77e288c&which=3&whichitem=2614&ajax=1&_=1538049902643 */
/*GET multiuse.php?whichitem=9926&action=useitem&ajax=1&quantity=5&pwd=f4f8b4fa4058649c98df8676a77e288c&_=1538049978485 */
func (kol *relay)InvUse(itemId string, quantity int) ([]byte, error) {
    httpClient := kol.HttpClient
    var finalUrl string
    if quantity > 1 {
        finalUrl = fmt.Sprintf("%s?whichitem=%s&action=useitem&ajax=1&quantity=%d&pwd=%s", multiuseUrl, itemId, quantity, kol.PasswordHash)
    } else {
        finalUrl = fmt.Sprintf("%s?whichitem=%s&pwd=%s&ajax=1&quantity=%d", invUseUrl, itemId, kol.PasswordHash, quantity)
    }

    req, err   := http.NewRequest("GET", finalUrl, nil)
    if err != nil {
        return nil, err
    }

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    return body, CheckResponseForErrors(resp, body)
}

/*GET inv_spleen.php?whichitem=1455&ajax=1&pwd=9059a8720a363a243871f6d5594ba897&quantity=1&_=1537894093043*/
func (kol *relay)InvSpleen(itemId string) ([]byte, error) {
    httpClient := kol.HttpClient
    finalUrl   := fmt.Sprintf("%s?whichitem=%s&pwd=%s&ajax=1&quantity=1", invSpleenUrl, itemId, kol.PasswordHash)
    req, err   := http.NewRequest("GET", finalUrl, nil)
    if err != nil {
        return nil, err
    }

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    return body, CheckResponseForErrors(resp, body)

}

/*
using:Yep.
pwd:6e7d95baa4a6a6d3cd1fb8ac6d1c82a6
whicheffect:54
*/
func (kol *relay)Uneffect(effectId string) ([]byte, error) {
    httpClient := kol.HttpClient

    params := url.Values{}
    params.Set("using",       "Yup.")
    params.Set("pwd",         kol.PasswordHash)
    params.Set("whicheffect", effectId)

    paramsBody := strings.NewReader(params.Encode())
    req, err   := http.NewRequest("POST", uneffectUrl, paramsBody)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    return body, CheckResponseForErrors(resp, body)
}

func (kol *relay) queryLChat() ([]byte, error) {
    httpClient := kol.HttpClient
    req, err    := http.NewRequest("GET", lChatUrl, nil)
    if err != nil {
        return nil, err
    }

    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    return body, CheckResponseForErrors(resp, body)
}

var passwordHashPatterns []*regexp.Regexp = []*regexp.Regexp {
    regexp.MustCompile(`name=["']?pwd["']? value=["']([^"']+)["']`),
    regexp.MustCompile(`pwd=([^&]+)`),
    regexp.MustCompile(`pwd = "([^"]+)"`),
}
func (kol *relay) ResolveCharacterData() error {
    bodyBytes, err := kol.queryLChat()
    if err != nil {
        return err
    }
    body := string(bodyBytes)

    kol.PasswordHash = ""
    for _, pattern := range passwordHashPatterns {
        match := pattern.FindStringSubmatch(body)
        if match != nil && len(match) > 0 {
            kol.PasswordHash = string(match[1])
            break
        }
    }

    if kol.PasswordHash == "" {
        return errors.New("Cannot find password hash?!")
    }

    // TODO: get player ID here
    return nil
}

func (kol *relay)HandleKoLException(err error, password string) error {
    if err == nil {
        return nil
    }

    kolError, ok := err.(*KoLError)
    if !ok {
        return err
    }

    if kolError.ErrorType == Rollover {
        fmt.Println("Looks like we are in rollover.  Just shut down.")
        return err
    } else if kolError.ErrorType == Disconnect {
        fmt.Println("Looks like we were disconnected.  Try to reconnect!")
        err = kol.LogIn(password)
        if err != nil {
            return err
        }
    } else if kolError.ErrorType == BadRequest {
        // Weird.  Just log it.
        fmt.Println("Exception due to bad request.  Logging it and ignoring it: ", kolError)
        return nil
    } else if kolError.ErrorType == ServerError {
        // Weird.  Just log it.
        fmt.Println("Server is having a bad time.  Logging it and ignoring it: ", kolError)
        return nil
    } else { // Some other error
        return err
    }

    return nil
}


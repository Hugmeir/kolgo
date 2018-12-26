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
    sendKMailUrl     = baseUrl + "sendmessage.php"
    sendGiftUrl      = baseUrl + "town_sendgift.php"
    showPlayerUrl    = baseUrl + "showplayer.php"
    apiUrl           = baseUrl + "api.php"
    curseUrl         = baseUrl + "curse.php"
    mallStoreUrl     = baseUrl + "mallstore.php"
    itemDescUrl      = baseUrl + "desc_item.php"
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
    LogIn()                    error
    LogOut()                   ([]byte, error)
    StartChatPoll()
    StartMessagePoll()
    AddHandler(int, handlerInterface)
    SendMessage(string, string)
    SendCommand(string, string)
    SendKMail(string, string, int, *map[*Item]int) ([]byte, error)
    SendGift(string, string, string, int, *map[*Item]int) ([]byte, error)
    APIRequest(string, *map[string]string) ([]byte, error)

    // Clan actions
    ClanHall()                 ([]byte, error)
    ClanApplications()         ([]byte, error)
    ClanWhitelist()            ([]byte, error)
    ClanMembers(int)           ([]byte, error)
    ClanStash()                ([]byte, error)
    ClanVIPFortune()           ([]byte, error)
    ClanVIPFax()               ([]byte, error)
    ClanVIPRecieveFax()        ([]byte, error)
    ClanVIPSendFax()           ([]byte, error)

    ClanTakeFromStash(*Item, int)                    ([]byte, error)
    ClanProcessApplication(string, bool)             ([]byte, error)
    ClanModifyMembers([]ClanMemberModification)      ([]byte, error)
    ClanAddWhitelist(string, string, string)         ([]byte, error)
    ClanRemoveWhitelist(string)                      ([]byte, error)
    ClanResponseLoveTest(string, string, string, string) ([]byte, error)

    ShowPlayer(string) ([]byte, error)

    ItemDescription(*Item) ([]byte, error)

    // Not-so-public interface:
    SubmitChat(string, string) ([]byte, error)
    PollChat()                 ([]byte, error)
    InvUse(*Item, int)         ([]byte, error)
    InvSpleen(*Item)           ([]byte, error)
    Uneffect(string)           ([]byte, error)
    DecodeChat([]byte)         (*ChatResponse, error)
    SenderIdFromMessage(ChatMessage) string
    Curse(string, *Item)       ([]byte, error)
    MallStore(string)          ([]byte, error)

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

var passwords sync.Map

type relay struct {
    UserName      string
    HttpClient    *http.Client
    SessionId     string
    PasswordHash  string
    LastSeen      string
    playerId      string
    APIReason     string

    reconnects    []time.Time

    Log           *os.File
    handlers      sync.Map

    AwayTicker    *time.Ticker
    MessagesC     chan *MessageToKoL
    RequestMutex  sync.Mutex
}

func NewKoL(userName string, password string, f *os.File) KoLRelay {
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
        playerId:   "",
        AwayTicker: time.NewTicker(3*time.Minute),
        PasswordHash: "",

        reconnects: make([]time.Time, 0, 5),
        MessagesC: make(chan *MessageToKoL, 200),
        Log: f,
        // TODO:
        APIReason: "kol-relay for " + userName,
    }

    passwords.Store(kol.UserName, password)

    return kol
}

func (kol *relay)PlayerId() string {
    return kol.playerId
}

func (kol *relay) LogIn() error {
    password, ok := passwords.Load(kol.UserName)
    if !ok {
        panic(errors.New(fmt.Sprintf("No password available for %s", kol.UserName)))
    }
    loginParams := url.Values{}
    loginParams.Set("loggingin",    "Yup.")
    loginParams.Set("loginname",    kol.UserName)
    loginParams.Set("password",     password.(string))
    loginParams.Set("secure",       "0")
    loginParams.Set("submitbutton", "Log In")

    loginBody := strings.NewReader(loginParams.Encode())
    req, err := http.NewRequest("POST", loginUrl, loginBody)
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    // Note: MUST use internal since we can be called from within DoHTTP()
    // if we need to reconnect
    _, err = kol.DoHTTPInternal(req)
    if err != nil {
        return err
    }

    for _, cookie := range kol.HttpClient.Jar.Cookies(req.URL) {
        if strings.EqualFold(cookie.Name, "PHPSESSID") {
            kol.SessionId = cookie.Value
        }
    }

    if kol.SessionId == "" {
        return errors.New("Failed to aquire session id")
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

func (kol *relay)StartMessagePoll() {
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
                fatalError := kol.HandleKoLException(err)
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
                if err != nil {
                    panic(err)
                }
        }
    }
}

func (kol *relay)StartChatPoll() {

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
                panic(err)
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

func (kol *relay) LogOut() ([]byte, error) {
    defer kol.AwayTicker.Stop()

    req, err := http.NewRequest("GET", logoutUrl, nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

func (kol *relay) ShowPlayer(id string) ([]byte, error) {
    req, err := http.NewRequest("GET", showPlayerUrl + "?who=" + id, nil)
    if err != nil {
        return nil, err
    }
    return kol.DoHTTP(req)
}

func (kol *relay) APIRequest(what string, args *map[string]string) ([]byte, error) {
    params := url.Values{}
    params.Set("what",      what)
    params.Set("for",       kol.APIReason)
    params.Set("pwd",       kol.PasswordHash)
    if args != nil {
        for k, v := range *args {
            params.Add(k, v)
        }
    }
    urlParams := params.Encode()
    body := strings.NewReader(urlParams)

    req, err := http.NewRequest("POST", apiUrl + "?" + urlParams, body)
    if err != nil {
        return nil, err
    }
    return kol.DoHTTP(req)
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

func (kol *relay)DoHTTPInternal(req *http.Request) ([]byte, error) {
    httpClient := kol.HttpClient

    req.Header.Set("Accept-Encoding", "gzip")
    req.Header.Set("X-Asym-Culprit",  "Maintained by Hugmeir(#3061055)")
    req.Header.Set("X-Asym-Reason",   "Uniting /clan and the clan Discord")
    req.Header.Set("X-Asym-Source",   "https://github.com/Hugmeir/kol-relay")

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

func SwapInNewPasswordHash(req *http.Request, oldBody []byte, oldHash, newHash string) *http.Request {
    newUrl := strings.Replace(req.URL.String(), oldHash, newHash, -1)
    var newRequest *http.Request
    var err error
    if len(oldBody) > 0 {
        newBody    := bytes.Replace(oldBody, []byte(oldHash), []byte(newHash), -1)
        newParams  := bytes.NewReader(newBody)
        newRequest, err = http.NewRequest(req.Method, newUrl, newParams)
    } else {
        newRequest, err = http.NewRequest(req.Method, newUrl, nil)
    }

    if err != nil {
        return nil
    }

    for k, values := range req.Header {
        for _, v := range values {
            newRequest.Header.Add(k, v)
        }
    }
    return newRequest
}

func (kol *relay)DoHTTP(req *http.Request) ([]byte, error) {
    // TODO:
    // Race condition...  Need to rewrite all of DoHTTP to take in the params to create a request,
    // with placeholders for the pwd hash
    oldHash  := kol.PasswordHash

    if strings.EqualFold(req.Method, `POST`) {
        // Can do as many GET requests with an old pwd hash as we want, it's POST that will screw us,
        // so no need to lock non-POST requests.
        kol.RequestMutex.Lock()
        defer kol.RequestMutex.Unlock()
    }

    newHash  := kol.PasswordHash

    var oldBody []byte // keep it around in case we need to retry
    if req.GetBody != nil {
        r, _           := req.GetBody()
        tempOldBody, _ := ioutil.ReadAll(r)
        oldBody = make([]byte, len(tempOldBody))
        copy(oldBody, tempOldBody)
    }

    if oldHash != newHash {
        req = SwapInNewPasswordHash(req, oldBody, oldHash, newHash)
        if req == nil {
            return nil, errors.New("Failed to recreate request with new password hash after reconnect")
        }
    }

    body, err := kol.DoHTTPInternal(req)
    if err == nil {
        return body, err
    }

    // Got an error -- can we retry?
    kolError, ok := err.(*KoLError)
    if !ok {
        return body, err
    }

    // Did we get disconnected?
    if kolError.ErrorType != Disconnect {
        return body, err
    }

    // Are we a logout?
    if strings.Contains(req.URL.Path, `logout.php`) {
        // Then a disconnect is, well, fine >.>
        return body, nil
    }

    // Attempt to reconnect:
    fatalErr := kol.HandleKoLException(err)
    if fatalErr != nil {
        return body, fatalErr
    }

    // We reconnected -- now try the request again, return regardless
    // of what the outcome is:
    // Shitty part: we need to replace the old pwd hash with the current one.
    // Must do this in the url & in the body
    newRequest := SwapInNewPasswordHash(req, oldBody, oldHash, kol.PasswordHash)
    if newRequest == nil {
        return body, errors.New("Failed to recreate request with new password hash after reconnect")
    }
    return kol.DoHTTPInternal(newRequest)
}

func (kol *relay) PollChat() ([]byte, error) {
    // j=1 in the url is critical, required to get json!
    req, err := http.NewRequest("GET", fmt.Sprintf("%s?lasttime=%s&j=1", newMessageUrl, kol.LastSeen), nil)
    if err != nil {
        return nil, err
    }
    // Critical that we request json here!
    req.Header.Set("Accept",          "application/json, text/javascript, */*; q=0.01")
    req.Header.Set("Refered",         "https://www.kingdomofloathing.com/mchat.php")

    return kol.DoHTTP(req)
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

func (kol *relay) Curse(recipient string, item *Item) ([]byte, error) {
    params := url.Values{}
    params.Set("pwd",          kol.PasswordHash)
    params.Set("action",       "use")
    params.Set("targetplayer", recipient)
    params.Set("whichitem",    item.ID)

    body := strings.NewReader(params.Encode())
    req, err := http.NewRequest("POST", curseUrl, body)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    return kol.DoHTTP(req)
}

/*
Request URL:http://127.0.0.1:60080/sendmessage.php?toid=2685812
Request Method:POST
Status Code:200 OK
Remote Address:127.0.0.1:60080
Response Headers
view source
Cache-Control:no-cache, must-revalidate
Content-Length:37217
Content-Type:text/html; charset=UTF-8
Date:Sat, 13 Oct 2018 14:28:41 GMT
Expires:Thu, 19 Nov 1981 08:52:00 GMT
Pragma:no-cache
Server:nginx/1.8.1
Set-Cookie:AWSALB=a1uofXnwjt6dQveifVrRaV/lBlIxuDvvIdeiiPchc9t9I5BYicH+Z4xc59BTDEAWvxRIR5qwe33/m1terJibTiRfGt0nBlZyhyMXnXfw2hfC+cl4nr3DhIloxO63; Expires=Sat, 20 Oct 2018 14:28:41 GMT; Path=/
Vary:Accept-Encoding
X-Powered-By:PHP/5.3.29
Request Headers
view source
Accept-Encoding:gzip, deflate, br
Accept-Language:en-US,en;q=0.8,es;q=0.6
Cache-Control:max-age=0
Connection:keep-alive
Content-Length:248
Content-Type:application/x-www-form-urlencoded
Cookie:charpwd=200; chatpwd=252; AWSALB=/6sa8hPj46GjzlCQqJJZpaKUuzWBP/05fiCW+ji7f445QflQRnBPSzHpSc4pFhyaYCLB9S6PUVes9bcIWPhFoJfhoXctBGOHyP4CwD51sgHL7URAVk7JCHH3sFjL
DNT:1
Host:127.0.0.1:60080
Origin:http://127.0.0.1:60080
Referer:http://127.0.0.1:60080/sendmessage.php?toid=2685812&replyid=136372106
Upgrade-Insecure-Requests:1
User-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36
Query String Parameters
view source
view URL encoded
toid:2685812
Form Data
view source
view URL encoded
action:send
replyid:136372106
pwd:e748e7bcee1ea8598d0babe8823d40ab
towho:2685812
contact:0
message:Do ignore this message, need to send out one kmail with an item to figure out how make the relay send 'em...
howmany1:1
whichitem1:131
sendmeat:1
*/

func (kol *relay) SendKMail(recipient string, message string, meat int, items *map[*Item]int) ([]byte, error) {
    params := url.Values{}
    params.Set("action",    "send")
    params.Set("towho",     recipient)
    params.Set("message",   message)
    params.Set("pwd",       kol.PasswordHash)
    if meat > 0 {
        params.Set("sendmeat", strconv.Itoa(meat))
    }

    if items != nil {
        idx := 0
        for i, m := range *items {
            idx++
            params.Set(fmt.Sprintf("whichitem%d", idx), i.ID)
            params.Set(fmt.Sprintf("howmany%d", idx), strconv.Itoa(m))
        }
    }

    kMailBody := strings.NewReader(params.Encode())
    req, err := http.NewRequest("POST", sendKMailUrl + "?toid=", kMailBody)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    return kol.DoHTTP(req)
}

func (kol *relay) SendGift(recipient string, message string, innerMessage string, meat int, items *map[*Item]int) ([]byte, error) {

    params := url.Values{}
    params.Set("action",     "Yep.")
    params.Set("towho",      recipient)
    // Must replace all newlines with \r\n, otherwise the game will translate them as "n".  Yep, plain 'n'
    params.Set("note",       strings.Replace(message, "\n", "\r\n", -1))
    params.Set("insidenote", strings.Replace(innerMessage, "\n", "\r\n", -1))
    params.Set("fromwhere",  "0") // 0 => inventory
    params.Set("pwd",        kol.PasswordHash)
    if meat > 0 {
        params.Set("sendmeat", strconv.Itoa(meat))
    }

    if items != nil {
        idx := 0
        for i, m := range *items {
            idx++
            params.Set(fmt.Sprintf("whichitem%d", idx), i.ID)
            params.Set(fmt.Sprintf("howmany%d", idx), strconv.Itoa(m))
        }
        if idx > 11 {
            return nil, errors.New(fmt.Sprintf("You can only send up to 11 items at once, you asked to send %d", idx))
        }
        params.Set("whichpackage", strconv.Itoa(idx))
    } else {
        params.Set("whichpackage", "1")
    }

    kMailBody := strings.NewReader(params.Encode())
    req, err := http.NewRequest("POST", sendGiftUrl, kMailBody)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    return kol.DoHTTP(req)
}

func (kol *relay) SubmitChat(destination string, message string) ([]byte, error) {
    kol.ResetAwayTicker()

    msg         := destination + url.QueryEscape(" " + message)
    finalUrl   := fmt.Sprintf("%s?playerid=%s&pwd=%s&j=1&graf=%s", submitMessageUrl, kol.playerId, kol.PasswordHash, msg)
    req, err := http.NewRequest("POST", finalUrl, nil)
    if err != nil {
        return nil, err
    }

    //req.Header.Set("User-Agent",      "KoL-chat-to-Discord relay")
    req.Header.Set("Refered",         "https://www.kingdomofloathing.com/mchat.php")

    body, err := kol.DoHTTP(req)

    if !strings.Contains(destination, "/who") {
        fmt.Fprintf(kol.Log, "%s %d [RESPONSE]: %s\n", time.Now().Format(time.RFC3339), os.Getpid(), string(body))
    }

    return body, err
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
func (kol *relay)InvUse(item *Item, quantity int) ([]byte, error) {
    var finalUrl string
    if quantity > 1 {
        finalUrl = fmt.Sprintf("%s?whichitem=%s&action=useitem&ajax=1&quantity=%d&pwd=%s", multiuseUrl, item.ID, quantity, kol.PasswordHash)
    } else {
        finalUrl = fmt.Sprintf("%s?whichitem=%s&pwd=%s&ajax=1&quantity=%d", invUseUrl, item.ID, kol.PasswordHash, quantity)
    }

    req, err   := http.NewRequest("GET", finalUrl, nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

/*GET inv_spleen.php?whichitem=1455&ajax=1&pwd=9059a8720a363a243871f6d5594ba897&quantity=1&_=1537894093043*/
func (kol *relay)InvSpleen(item *Item) ([]byte, error) {
    finalUrl   := fmt.Sprintf("%s?whichitem=%s&pwd=%s&ajax=1&quantity=1", invSpleenUrl, item.ID, kol.PasswordHash)
    req, err   := http.NewRequest("GET", finalUrl, nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

/*
using:Yep.
pwd:6e7d95baa4a6a6d3cd1fb8ac6d1c82a6
whicheffect:54
*/
func (kol *relay)Uneffect(effectId string) ([]byte, error) {
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

    return kol.DoHTTP(req)
}

func (kol *relay) queryLChat() ([]byte, error) {
    req, err    := http.NewRequest("GET", lChatUrl, nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTPInternal(req)
}

func (kol *relay) MallStore(storeId string) ([]byte, error) {
    req, err   := http.NewRequest("GET", fmt.Sprintf("%s?whichstore=%s", mallStoreUrl, storeId), nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

func (kol *relay)ItemDescription(item *Item) ([]byte, error) {
    finalUrl   := fmt.Sprintf("%s?whichitem=%s", itemDescUrl, item.DescID)
    req, err   := http.NewRequest("GET", finalUrl, nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

var passwordHashPatterns = []*regexp.Regexp {
    regexp.MustCompile(`name=["']?pwd["']? value=["']([^"']+)["']`),
    regexp.MustCompile(`pwd=([^&]+)`),
    regexp.MustCompile(`pwd = "([^"]+)"`),
}
var playerIDPatterns = []*regexp.Regexp {
    regexp.MustCompile(`\bvar playerid\s*=\s*([0-9]+);`),
    regexp.MustCompile(`\bplayerid=([0-9]+)&pwd=`),
}
func (kol *relay) ResolveCharacterData() error {
    bodyBytes, err := kol.queryLChat()
    if err != nil {
        return err
    }
    body := string(bodyBytes)

    kol.playerId     = ""
    kol.PasswordHash = ""
    for _, pattern := range playerIDPatterns {
        match := pattern.FindStringSubmatch(body)
        if match != nil && len(match) > 0 {
            kol.playerId = string(match[1])
            break
        }
    }

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

    if kol.playerId == "" {
        return errors.New("Cannot find player ID?!")
    }

    // TODO: get player ID here
    return nil
}

func (kol *relay)ShouldReconnect() bool {
    r := kol.reconnects
    now := time.Now()

    if len(r) < 2 {
        // Don't even bother
        kol.reconnects = append(r, now)
        return true
    }

    // Filter out old reconnects
    f := make([]time.Time, 0, 5)
    for _, t := range r {
        if now.Sub(t).Minutes() < 1 {
            // Less than one minute, so keep it
            f = append(f, t)
        }
    }

    // Okay, so now f is all the recent reconnects; replace kol.reconnects
    f = append(f, now)
    kol.reconnects = f
    if len(f) > 2 {
        // We had at least three 3 reconnects in the last mintue.  That's way too many.
        return false
    }

    return true
}

func (kol *relay)HandleKoLException(err error) error {
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
        if !kol.ShouldReconnect() {
            return errors.New(fmt.Sprintf("Reconnected too many times in too short a period of time!\nActual error: %s", err))
        }
        fmt.Println("Looks like we were disconnected.  Try to reconnect!")
        err = kol.LogIn()
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


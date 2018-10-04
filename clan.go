package kolgo

import (
    "strings"
    "net/http"
    "net/url"
)

const (
    clanHallUrl         = baseUrl + "clan_hall.php"
    clanApplicationsUrl = baseUrl + "clan_applications.php"
    clanWhitelistUrl    = baseUrl + "clan_whitelist.php"
)

func (kol *relay)ClanHall() ([]byte, error) {
    req, err := http.NewRequest("GET", clanHallUrl, nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

func (kol *relay)ClanApplications() ([]byte, error) {
    req, err := http.NewRequest("GET", clanApplicationsUrl, nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

func (kol *relay)ClanAcceptApplication(requestID string) ([]byte, error) {
    params := url.Values{}
    params.Set("action",      "process")
    params.Set("pwd",         kol.PasswordHash)
    params.Set(requestID,     "1")

    paramsBody := strings.NewReader(params.Encode())
    req, err := http.NewRequest("POST", clanApplicationsUrl, paramsBody)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    return kol.DoHTTP(req)
}

func (kol *relay)ClanMembers(page string) ([]byte, error) {
    req, err := http.NewRequest("GET", clanWhitelistUrl + "?begin=" + page, nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

func (kol *relay)ClanModifyMember(page string, playerID string, level string, title string) ([]byte, error) {
    //_, month, day := time.Now().Date()
    //title := fmt.Sprintf("%02/%02d awaiting Naming Day", int(month), day)

    params := url.Values{}
    params.Set("pwd",              kol.PasswordHash)
    params.Set("action",           "modify")
    params.Set("begin",            "page")
    params.Set("pids[]",           playerID)
    params.Set("level" + playerID, level)
    params.Set("title" + playerID, title)

    paramsBody := strings.NewReader(params.Encode())
    req, err := http.NewRequest("POST", clanWhitelistUrl, paramsBody)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    return kol.DoHTTP(req)
}


func (kol *relay)ClanWhitelist() ([]byte, error) {
    req, err := http.NewRequest("GET", clanWhitelistUrl, nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

func (kol *relay)ClanAddWhitelist(playerName string, level string, title string) ([]byte, error) {
    params := url.Values{}
    params.Set("pwd",         kol.PasswordHash)
    params.Set("action",      "add")
    params.Set("clannie",     "0")
    params.Set("addwho",      playerName)
    params.Set("level",       level)
    params.Set("title",       title)

    paramsBody := strings.NewReader(params.Encode())
    req, err := http.NewRequest("POST", clanWhitelistUrl, paramsBody)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    return kol.DoHTTP(req)
}



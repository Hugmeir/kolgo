package kolgo

import (
    "strings"
    "strconv"
    "net/http"
    "net/url"
)

const (
    clanHallUrl         = baseUrl   + "clan_hall.php"
    clanApplicationsUrl = baseUrl   + "clan_applications.php"
    clanWhitelistUrl    = baseUrl   + "clan_whitelist.php"
    clanMembersUrl      = baseUrl   + "clan_members.php"
    clanDetailedRosterUrl = baseUrl + "clan_detailedroster.php"
)

func (kol *relay)ClanHall() ([]byte, error) {
    req, err := http.NewRequest("GET", clanHallUrl, nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

func (kol *relay)ClanDetailedRoster() ([]byte, error) {
    req, err := http.NewRequest("GET", clanDetailedRosterUrl, nil)
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

func (kol *relay)ClanProcessApplication(requestID string, accept bool) ([]byte, error) {
    params := url.Values{}
    params.Set("action",      "process")
    params.Set("pwd",         kol.PasswordHash)
    if accept {
        params.Set(requestID,     "1")
    } else {
        params.Set(requestID,     "2")
    }

    paramsBody := strings.NewReader(params.Encode())
    req, err := http.NewRequest("POST", clanApplicationsUrl, paramsBody)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    return kol.DoHTTP(req)
}

func (kol *relay)ClanMembers(page int) ([]byte, error) {
    req, err := http.NewRequest("GET", clanMembersUrl + "?begin=" + strconv.Itoa(page) + "&num_per_page=100", nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

type ClanMemberModification struct {
    ID     string
    RankID string
    Title  string
}
func (kol *relay)ClanModifyMembers(clannies []ClanMemberModification) ([]byte, error) {
    var buf strings.Builder
    buf.WriteString(`pwd=`)
    buf.WriteString(url.QueryEscape(kol.PasswordHash))

    buf.WriteByte('&')
    buf.WriteString(`action=modify`)

    buf.WriteByte('&')
    buf.WriteString(`begin=page`)

    for _, m := range clannies {
        id := m.ID
        buf.WriteByte('&')
        buf.WriteString(url.QueryEscape(`pids[]`))
        buf.WriteByte('=')
        buf.WriteString(url.QueryEscape(id))

        if m.Title == "" {
            // Not passing a title will give you a blank title, which is lousy.
            continue
        }
        if m.RankID != "" {
            buf.WriteByte('&')
            buf.WriteString(url.QueryEscape(`level`+id))
            buf.WriteByte('=')
            buf.WriteString(url.QueryEscape(m.RankID))
        }
        buf.WriteByte('&')
        buf.WriteString(url.QueryEscape(`title`+id))
        buf.WriteByte('=')
        buf.WriteString(url.QueryEscape(m.Title))
    }

    e := buf.String()
    paramsBody := strings.NewReader(e)
    req, err := http.NewRequest("POST", clanMembersUrl, paramsBody)
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



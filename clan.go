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
    clanStashUrl        = baseUrl   + "clan_stash.php"

    // VIP
    clanVIPUrl          = baseUrl   + "clan_viplounge.php"
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

/*
action:updatewl
pwd:6b763b3d48ed3bc0b6d368c03548b08e
who:2685812
remove:Remove
*/
func (kol *relay)ClanRemoveWhitelist(playerID string) ([]byte, error) {
    params := url.Values{}
    params.Set("pwd",         kol.PasswordHash)
    params.Set("action",      "updatewl")
    params.Set("remove",      "Remove")
    params.Set("who",         playerID)

    paramsBody := strings.NewReader(params.Encode())
    req, err := http.NewRequest("POST", clanWhitelistUrl, paramsBody)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

func (kol *relay) ClanStash() ([]byte, error) {
    req, err := http.NewRequest("GET", clanStashUrl, nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

func (kol *relay) ClanTakeFromStash(item *Item, amount int) ([]byte, error) {
    params := url.Values{}
    params.Set("pwd",         kol.PasswordHash)
    params.Set("action",      "takegoodies")
    params.Set("quantity",    strconv.Itoa(amount))
    params.Set("whichitem",   item.ID)

    paramsBody := strings.NewReader(params.Encode())
    req, err := http.NewRequest("POST", clanStashUrl, paramsBody)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    return kol.DoHTTP(req)
}

func (kol *relay)ClanVIPFax() ([]byte, error) {
    req, err := http.NewRequest("GET", clanVIPUrl + "?preaction=faxmachine&whichfloor=2", nil)
    if err != nil {
        return nil, err
    }
    return kol.DoHTTP(req)
}

func (kol *relay)ClanVIPRecieveFax() ([]byte, error) {
    params := url.Values{}
    params.Set(`preaction`, `receivefax`)
    params.Set(`whichfloor`, `2`)
    paramsBody := strings.NewReader(params.Encode())
    req, err := http.NewRequest("POST", clanVIPUrl, paramsBody)
    if err != nil {
        return nil, err
    }
    return kol.DoHTTP(req)
}

func (kol *relay)ClanVIPSendFax() ([]byte, error) {
    params := url.Values{}
    params.Set(`preaction`, `sendfax`)
    params.Set(`whichfloor`, `2`)
    paramsBody := strings.NewReader(params.Encode())
    req, err := http.NewRequest("GET", clanVIPUrl, paramsBody)
    if err != nil {
        return nil, err
    }
    return kol.DoHTTP(req)
}

func (kol *relay)ClanVIPFortune() ([]byte, error) {
    req, err := http.NewRequest("GET", clanVIPUrl + "?preaction=lovetester", nil)
    if err != nil {
        return nil, err
    }

    return kol.DoHTTP(req)
}

// Thanks Parry:
/*  string foo = "clan_viplounge.php?preaction=dotestlove&testlove=" + id + "&pwd&option=1&q1=fries&q2=robin&q3=thin";*/
func (kol *relay)ClanResponseLoveTest(recipientID, answer1, answer2, answer3 string) ([]byte, error) {
    params := url.Values{}
    params.Set("pwd",         kol.PasswordHash)
    params.Set("preaction",   "dotestlove")
    params.Set("testlove",    recipientID)

    params.Set("option",   "1") // Clannie

    params.Set("q1",   answer1)
    params.Set("q2",   answer2)
    params.Set("q3",   answer3)

    paramsBody := strings.NewReader(params.Encode())
    req, err := http.NewRequest("POST", clanVIPUrl, paramsBody)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    return kol.DoHTTP(req)
}


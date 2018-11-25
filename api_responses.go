package kolgo

import (
    "fmt"
    "bytes"
    "strings"
    "strconv"
    "regexp"
    "time"
    "encoding/json"
)

func gameTZToTime(tz interface{}) time.Time {
    s := gameFieldToString(tz)
    i, err := strconv.ParseInt(s, 10, 64)
    if err != nil {
        return time.Now()
    } else {
        return time.Unix(i, 0)
    }
}

// I don't trust *any* of the fields that hold numbers as strings.  Betting
// it's one action-at-a-distance away from becoming plain ints.  So let's
// be paranoid
// TODO: Should build an unmarshaller...
func gameFieldToString(f interface{}) string {
    switch f.(type) {
        case string:
            return f.(string)
        case float64:
            return strconv.FormatInt(int64(f.(float64)), 10)
        default:
            return ""
    }
}

/*
Events:
[{"localtime":"10\/12\/18 08:08:34 AM","azunixtime":"1539349714","message":"New message received from <a target=mainpane href='showplayer.php?who=3061055'><font color=green>Hugmeir<\/font><\/a>.","payload":{"from":"3061055","id":136369118}}]
*/
func DecodeAPIEvent(b []byte) ([]APIEvent, error) {
    var raw []map[string]interface{}
    err := json.Unmarshal(b, &raw)
    if err != nil {
        return nil, err
    }

    events := make([]APIEvent, 0, len(raw))
    if len(raw) == 0 {
        return events, nil
    }

    for _, r := range raw {
        e := APIEvent{
            Payload: make(map[string]string),
        }
        if aztime, ok := r[`azunixtime`]; ok {
            e.Time = gameTZToTime(aztime)
        } else {
            e.Time = time.Now()
        }

        if msg, ok := r[`message`]; ok {
            e.Message = gameFieldToString(msg)
        }

        if payloadRaw, ok := r[`payload`]; ok {
            payload, ok := payloadRaw.(map[string]interface{})
            if !ok {
                continue
            }
            for k, v := range payload {
                s := gameFieldToString(v)
                e.Payload[k] = s
            }
        }

        events = append(events, e)
    }

    return events, nil
}


/*
[{"id":"136369118","type":"normal","fromid":"3061055","azunixtime":"1539349714","message":"sending the kmail events<center><table class=\"item\" style=\"float: none\" rel=\"id=4508&s=0&q=0&d=0&g=0&t=1&n=1&m=1&p=0&u=u\"><tr><td><img src=\"https:\/\/s3.amazonaws.com\/images.kingdomofloathing.com\/itemimages\/drinkme.gif\" alt=\"&quot;DRINK ME&quot; potion\" title=\"&quot;DRINK ME&quot; potion\" class=hand onClick='descitem(830929931)'><\/td><td valign=center class=effect>You acquire an item: <b>&quot;DRINK ME&quot; potion<\/b><\/td><\/tr><\/table><\/center><center><table><tr><td><img src=\"https:\/\/s3.amazonaws.com\/images.kingdomofloathing.com\/itemimages\/meat.gif\" height=30 width=30 alt=\"Meat\"><\/td><td valign=center>You gain 1 Meat.<\/td><\/tr><\/table><\/center>","fromname":"Hugmeir","localtime":"10\/12\/18 08:08:34 AM"},{"id":"136308980","type":"normal","fromid":"3152049","azunixtime":"1538671124","message":"Hi, and welcome to FCA!\n\nCome hang out in chat (type '\/c clan' in the chat pane) to get a title and get ranked up to Pleasure Seeker.\n\nOnce you are ranked up, you'll be able to access the clan stash and clan dungeon, and you'll automatically get a whitelist too!  Please read the rules for dungeon use in the clan forum, or ask in chat.\n\nFeel free to join the clan Discord: https:\/\/discord.gg\/CmSfAgq","fromname":"RelayBot","localtime":"10\/04\/18 11:38:44 AM"},{"id":"136308344","type":"normal","fromid":"7007","azunixtime":"1538663803","message":"Welcome back, ToilBot!  I'm pleased to see you've decided to try out another day of adventuring.<p>Here's a little something with which to wet
your whistle.  Enjoy!<p>-XOXO, the Toot Oriole<center><table class=\"item\" style=\"float: none\" rel=\"id=4855&s=0&q=0&d=0&g=0&t=0&n=1&m=0&p=0&u=u\"><tr><td><img src=\"https:\/\/s3.amazonaws.com\/images.kingdomofloathing.com\/itemimages\/plainbrown.gif\" alt=\"Toot Oriole care package\" title=\"Toot Oriole care package\" class=hand onClick='descitem(926193075)'><\/td><td valign=center class=effect>You acquire an item: <b>Toot Oriole care package<\/b><\/td><\/tr><\/table><\/center>","fromname":"Toot Oriole","localtime":"10\/04\/18 09:36:43 AM"},{"id":"136302462","type":"giftshop","fromid":"3061055","azunixtime":"1538598141","message":"<center><table class=\"item\" style=\"float: none\" rel=\"id=1168&s=0&q=0&d=0&g=1&t=0&n=1&m=0&p=0&u=.\"><tr><td><img src=\"https:\/\/s3.amazonaws.com\/images.kingdomofloathing.com\/itemimages\/lessthan3.gif\" alt=\"less-than-three-shaped box\" title=\"less-than-three-shaped box\" class=hand onClick='descitem(938194457)'><\/td><td valign=center class=effect>You acquire an item: <b>less-than-three-shaped box<\/b><\/td><\/tr><\/table><\/center><p>Inside Note:<p><center><table class=\"item\" style=\"float: none\" rel=\"id=2614&s=125&q=0&d=1&g=0&t=1&n=3&m=1&p=0&u=u\"><tr><td><img src=\"https:\/\/s3.amazonaws.com\/images.kingdomofloathing.com\/itemimages\/filter.gif\" alt=\"mojo filter\" title=\"mojo filter\" class=hand onClick='descitem(551940191)'><\/td><td valign=center class=effect>You acquire <b>3 mojo filters<\/b><\/td><\/tr><\/table><\/center><center><table class=\"item\" style=\"float: none\" rel=\"id=9958&s=30&q=0&d=1&g=0&t=1&n=6&m=0&p=0&u=s&ou=use\"><tr><td><img src=\"https:\/\/s3.amazonaws.com\/images.kingdomofloathing.com\/itemimages\/purplebeast.gif\" alt=\"Purple Beast energy drink\" title=\"Purple Beast energy drink\" class=hand onClick='descitem(522759471)'><\/td><td valign=center class=effect>You acquire <b>6 Purple Beast energy d
rinks<\/b><\/td><\/tr><\/table><\/center>","fromname":"Hugmeir","localtime":"10\/03\/18 03:22:21 PM"}]
*/

var kmailTextMatcher = regexp.MustCompile(`(?si)\A([^<]*)(.*)\z`)
var kmailMeatMatcher = regexp.MustCompile(`>You gain ([0-9.,]+) Meat\.<`)
var kmailItemMatcher = regexp.MustCompile(`onClick=['"]descitem\((\d+)\)['"][^>]*>\s*</td>\s*<td[^>]*>You acquire (an item: <b>|<b>[0-9,.]+\s+)([^<]+)</b>`)
var kmailInsideNote  = regexp.MustCompile(`(?i)<p>Inside Note:<p>([^<]*)<`)
var kmailMaybeNumber = regexp.MustCompile(`[0-9]+(?:[.,][0-9]+)*`)
func unprettifyNumers(s string) string {
    return strings.Replace(strings.Replace(s, `.`, ``, -1), `,`, ``, -1)
}
func decodeKMailBody(s string) KMailMessage {
    kmail := KMailMessage{
        MessageRaw: s,
        Items:      map[*Item]int{},
    }

    m := kmailTextMatcher.FindStringSubmatch(s)
    kmail.Message = m[1]

    if m[2] == "" {
        return kmail
    }

    // Okay... need to parse out the items & the meat, if any
    extra := m[2]

    insideNoteM := kmailInsideNote.FindStringSubmatch(extra)
    if len(insideNoteM) > 0 {
        kmail.InnerMessage = &KMailMessage{
            MessageRaw: extra,
            Message:    insideNoteM[1],
            Items:      map[*Item]int{},
        }
    }

    m2 := kmailMeatMatcher.FindStringSubmatch(extra)
    if len(m2) > 0 {
        meat := unprettifyNumers(m2[1])
        i, _ := strconv.Atoi(meat)
        if kmail.InnerMessage != nil {
            kmail.InnerMessage.Meat = i
        } else {
            kmail.Meat = i
        }
    }

    // And now, items:
    m3 := kmailItemMatcher.FindAllStringSubmatch(extra, -1)
    if len(m3) == 0 {
        return kmail
    }

    for idx, m := range m3 {
        amount   := 1
        descID    := m[1]
        rawAmount := m[2]
        itemName  := m[3]
        item     := DescIDToItem(descID)
        if item == nil {
            item, _ = ToItem(itemName)
        }

        if item == nil {
            fmt.Println("No clue what to do with item ", m[0])
            continue
        }

        if !strings.Contains(rawAmount, `an item:`) {
            num := kmailMaybeNumber.FindStringSubmatch(rawAmount)
            if len(num) > 0 {
                amount, _ = strconv.Atoi(unprettifyNumers(num[0]))
            }
        }

        if amount <= 0 {
            amount = 1
        }

        if kmail.InnerMessage != nil && idx > 0 {
            kmail.InnerMessage.Items[item] = amount
        } else {
            kmail.Items[item] = amount
        }
    }

    return kmail
}

func DecodeAPIKMail(b []byte) (*KMail, error) {
    if b[0] != '[' {
        b = append(append([]byte{'['}, b...), ']')
    }

    kmails, err := DecodeAPIKMails(b)
    if err != nil {
        return nil, err
    }

    if len(kmails) == 0 {
        return nil, nil
    }

    return kmails[0], nil
}

func DecodeAPIKMails(b []byte) ([]*KMail, error) {
    var raw []map[string]interface{}
    err := json.Unmarshal(b, &raw)
    if err != nil {
        return nil, err
    }

    kmails := make([]*KMail, 0, len(raw))
    if len(raw) == 0 {
        return kmails, nil
    }

    for _, r := range raw {
        kmail := &KMail{}
        if rawMessage, ok := r[`message`]; ok {
            msg := decodeKMailBody(gameFieldToString(rawMessage))
            kmail.Message = msg
        } else {
            fmt.Println("kmail without a message field... what?", string(b))
            continue
        }

        id := "-1"
        if rawID, ok := r[`id`]; ok {
            id = gameFieldToString(rawID)
        }
        kmail.ID = id

        mailType := `normal`
        if rawType, ok := r[`type`]; ok {
            mailType = gameFieldToString(rawType)
        }
        kmail.Type = mailType

        var playerName, playerID string
        if rawID, ok := r[`fromid`]; ok {
            playerID = gameFieldToString(rawID)
        } else {
            playerID = "-1"
        }
        if rawName, ok := r[`fromname`]; ok {
            playerName = gameFieldToString(rawName)
        }
        kmail.From = Player{
            Name: playerName,
            ID:   playerID,
        }

        kmails = append(kmails, kmail)
    }

    return kmails, nil
}

/*
<input type=submit class=button value='Add Items to Clan Stash'></form><p><b>Take an item
 from the Goodies Hoard:</b><br><form name=takegoodies action=clan_stash.php method=post><input type=hidden name=pwd value='d8a051ec44dccb6daee688d31fa366ef'><input type=hidden name
=action value="takegoodies"><img src='https://s3.amazonaws.com/images.kingdomofloathing.com/itemimages/magnify.gif' style='vertical-align: middle; cursor: pointer' onClick='describe
(document.takegoodies.whichitem);' title='View Item Description' alt='View Item Description'> <input class=text size=2 type=text name=quantity value=1> <select name=whichitem><optio
n value=4508 descid=830929931>&quot;DRINK ME&quot; potion (755) (-0)</option><option value=7772 descid=950823191>&quot;meat&quot; stick (80) (-55)</option><option value=3137 descid=
*/
var inStashMatcher   = regexp.MustCompile(`(?i)Take an item from the Goodies Hoard:.+`)
var stashItemMatcher = regexp.MustCompile(`(?i)<option[^<]+value=['"]?(\d+)`)
func DecodeClanStash(b []byte) []*Item {
    m := inStashMatcher.FindStringSubmatch(string(b))
    if len(m) < 1 {
        return nil
    }

    matches := stashItemMatcher.FindAllStringSubmatch(m[0], -1)
    items   := make([]*Item, 0, len(matches))
    for _, m := range matches {
        itemID, _ := strconv.Atoi(m[1])
        item,   _ := ToItem(itemID)
        if item == nil {
            fmt.Println("Could not figure out what this item is: ", m[1])
            continue
        }
        items = append(items, item)
    }

    return items
}

// Love consults
/*
You have active relationship consultations open with: <br /><a href="/clan_v
iplounge.php?preaction=testlove&testlove=918470">Ikkie</a><br /><a href="/clan_viplounge.php?preaction=testlove&testlove=2416558">Nescire</a><br /><a href="/clan_viplounge.php?preac
tion=testlove&testlove=2707364">StiffKnees</a><br /><a href="/clan_viplounge.php?preaction=testlove&testlove=3061055">Hugmeir</a><br /></font><p>
*/
var loveConsultMatcher = regexp.MustCompile(`(?i)<a[^>]+href=['"]/?clan_viplounge.php([^"']+)["'][^>]*>([^<]+)</a>`)
var testLoveMatcher    = regexp.MustCompile(`(?i)testlove=([0-9]+)`)
func DecodeOutstandingZataraConsults(b []byte) []*Player {
    if !bytes.Contains(b, []byte(`You have active relationship consultations open with`)) {
        return nil
    }

    matches := loveConsultMatcher.FindAllStringSubmatch(string(b), -1)

    if len(matches) < 1 {
        return nil
    }

    players := make([]*Player, 0, len(matches))
    for _, m := range matches {
        url  := m[1]
        name := m[2]
        if !strings.Contains(url, `preaction=testlove`) {
            continue
        }

        innerm := testLoveMatcher.FindStringSubmatch(url)
        if len(innerm) == 0 {
            continue
        }
        id := innerm[1]
        players = append(players, &Player{
            ID:   id,
            Name: name,
        })
    }

    return players
}

/*
<input name="whichitem" type="radio" value="4358001699000" onclick="selecteditem=4358001699000"></td><td><img src="/images/itemimages/book3.gif" class="hand   " onclick="descitem(981406827)"></td><td valign="center"><b>A Crimbo Carol, Ch. 5</b> (1) </td><td>1,699,000 Meat</td></tr><tr><td><input name="whichitem" type="radio" value="883   1198123123" onclick="selecteditem=8831198123123"></td><td><img src="/images/itemimages/baskinrobin.gif" class="hand" onclick="descitem(662653769)"></td><td valign="center"><b>bas   king robin</b> (1) </td><td>198,123,123 Meat</td></tr><tr><td><input name="whichitem" type="radio" value="9927999999999" onclick="selecteditem=9927999999999"></td><td><img src="/   images/itemimages/bbattcrate.gif" class="
*/
var mallEntryMatcher = regexp.MustCompile(`(?i)value=["']?([0-9]+)["']?.+?descitem\(([^\)]+)\).+?</b> \(([0-9,]+)\)`)
func DecodeMallStore(b []byte) []MallEntry {
    matches := mallEntryMatcher.FindAllStringSubmatch(string(b), -1)
    entries := make([]MallEntry, 0, len(matches))
    for _, m := range matches {
        value, _ := strconv.Atoi(m[1])
        descID   := m[2]
        item     := DescIDToItem(descID)
        amount, _ := strconv.Atoi(strings.Replace(m[3], `,`, ``, -1))
        entries  = append(entries, MallEntry{
            Item: item,
            Price: value,
            Amount: amount,
        })
    }
    return entries
}


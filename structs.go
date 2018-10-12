package kolgo

import (
    "time"
)

type APIEvent struct {
    Time       time.Time
    Message    string
    Payload    map[string]string
}

type Player struct {
    ID   string
    Name string
}

type KMailMessage struct {
    MessageRaw   string
    Message      string
    Meat         int
    Items        map[*Item]int
    // Will be true if this was a gift, and the giftbox was opened:
    InnerMessage *KMailMessage
}

type KMail struct {
    ID      string
    Type    string
    From    Player
    Time    time.Time
    Message KMailMessage
}


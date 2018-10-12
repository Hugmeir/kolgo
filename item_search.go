package kolgo

import (
    "fmt"
    "errors"
    "strings"
)

type ItemTrie struct {
    Item     *Item
    Children map[rune]*ItemTrie
}

func MakeItemTrie() *ItemTrie {
    return &ItemTrie{
        Children: make(map[rune]*ItemTrie),
    }
}

func (node *ItemTrie) Add(k string, item *Item) {
    for _, r := range k {
        c, ok := node.Children[r]
        if !ok || c == nil {
            c = MakeItemTrie()
            node.Children[r] = c
        }
        node = c
    }
    node.Item = item
}

func (node *ItemTrie) Get(k string) *Item {
    for _, r := range k {
        node, _ = node.Children[r]
        if node == nil {
            return nil
        }
    }
    return node.Item
}

func (node *ItemTrie)GetNearby(k string, want int) []*Item {
    nearby := make([]*Item, 0, want)
    for _, r := range k {
        node, _ = node.Children[r]
        if node == nil {
            return nearby
        }
    }

    if node.Item != nil {
        want--
        nearby = append(nearby, node.Item)
    }

    if want <= 0 || len(node.Children) == 0 {
        return nearby
    }

    // Iterative approach, since the worst case
    // scenario is only a couple thousand nodes on the
    // stack, and it's way easier to tweak >.>
    nodes := make([]*ItemTrie, 0, 10)
    for _, n := range node.Children {
        nodes = append(nodes, n)
    }
    for i := 0; i < len(nodes); i++ {
        inner := nodes[i]
        if inner.Item != nil {
            want--
            nearby = append(nearby, inner.Item)
        }

        if want <= 0 {
            return nearby
        }

        for _, n := range inner.Children {
            nodes = append(nodes, n)
        }
    }

    return nearby
}

var itemTrie *ItemTrie
var itemDescIDToItem map[string]*Item
func init() {
    itemTrie     = MakeItemTrie()
    itemDescIDToItem = make(map[string]*Item, len(AllItems))

    for _, item := range AllItems {
        if item == nil {
            continue
        }
        itemTrie.Add(item.Name, item)
        itemTrie.Add(strings.ToLower(item.Name), item)
        if item.Plural != "" {
            itemTrie.Add(strings.ToLower(item.Plural), item)
        }

        itemDescIDToItem[item.DescID] = item
    }
}

func DescIDToItem(descID string) *Item {
    i, _ := itemDescIDToItem[descID]
    return i
}

func ToItem(key interface{}) (*Item, error) {
    if ix, ok := key.(int); ok {
        if ix > len(AllItems) {
            return nil, errors.New(fmt.Sprintf("Passed item ID beyond the scope of known items -- Got %d", ix))
        }
        return AllItems[ix], nil
    }

    str, ok := key.(string)
    if !ok {
        return nil, errors.New("No clue what to do with this argument")
    }

    i := itemTrie.Get(str)
    if i != nil {
        return i, nil
    }

    alts := itemTrie.GetNearby(str, 2)
    if len(alts) == 1 {
        return alts[0], nil
    }

    if len(alts) == 0 {
        return nil, errors.New("Could not find the item " + str)
    }

    msg := fmt.Sprintf("Too many matches for '%s', stopped after getting %s, %s", str, alts[0].Name, alts[1].Name)
    return nil, errors.New(msg)
}

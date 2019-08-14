package falconsdk

import (
    "sync"
    "fmt"
    "time"
    "io/ioutil"
    "net/http"
    "net/url"
    "encoding/json"
)

type accessToken struct {
    Token string `json:"access_token"`
    TokenType string `json:"token_type"`
    ExpiresIn int64 `json:"expires_in"`
}

type clientImpl struct {
    sync.Mutex
    expire *time.Timer
    clientId string
    clientSecret string
    accessToken string
    streamToken string
}

func NewApiClient(clientId string, clientSecret string) FalconApi {
    client := &clientImpl{ clientId: clientId, clientSecret: clientSecret }
    token := client.doAuthorize()
    client.accessToken = token.Token

    timer := time.NewTimer(time.Duration(token.ExpiresIn - 5 * 60) * time.Second)
    client.expire = timer
    go client.refresh()

    return client
}

func (client clientImpl) getAccessToken() string {
    client.Lock()
    defer client.Unlock()
    return client.accessToken
}

func (client *clientImpl) refresh() {
    for {
        <- client.expire.C
        token := client.doAuthorize()
        client.Lock()
        client.accessToken = token.Token
        client.expire = time.NewTimer(time.Duration(token.ExpiresIn - 5 * 60) * time.Second)
        client.Unlock()
    }
}

func (client clientImpl) doAuthorize() *accessToken {
    params := url.Values{}
    params.Set("client_id", client.clientId)
    params.Set("client_secret", client.clientSecret)
    res, err := http.PostForm(fmt.Sprintf("%s%s", apiBaseUrl, authUrl), params)
    if err != nil {
        panic(err)
    }
    defer res.Body.Close()
    rawString, err := ioutil.ReadAll(res.Body)
    if err != nil {
        panic(err)
    }
    var token accessToken
    if err := json.Unmarshal(rawString, &token); err != nil {
        panic(err)
    }
    return &token
}

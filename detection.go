package falconsdk

import (
    "fmt"
    "net/http"
    "encoding/json"
    "io/ioutil"
)

type findDetectionIDsResult struct {
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
    Resources []string `json:"resources"`
}

func (client clientImpl) FindDetections(q string) []string {
    httpClient := &http.Client{}
    req, err := http.NewRequest("GET", fmt.Sprintf("%s%s", apiBaseUrl, findDetectionIDsUrl), nil)
    if err != nil {
        panic(err)
    }
    query := req.URL.Query()
    accessToken := client.getAccessToken()
    query.Add("q", q)
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
    var result findDetectionIDsResult
    if err := json.Unmarshal(rawString, &result); err != nil {
        panic(err)
    }
    return result.Resources
}

package falconsdk

const (
    apiBaseUrl = "https://api.crowdstrike.com"
    findDetectionIDsUrl = "/detects/queries/detects/v1"
    authUrl = "/oauth2/token"
    discoverStreamUrl = "/sensors/entities/datafeed/v2"
)

type FalconApi interface {
    FindDetections(q string) []string
    StartStreaming(appId string, offset int64, subscriber EventSubscriber)
}


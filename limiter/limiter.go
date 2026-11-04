package limiter

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
	"github.com/wyx2685/v2node/common/rate"
)

var limitLock sync.RWMutex
var limiter map[string]*Limiter

func Init() {
	limiter = map[string]*Limiter{}
}

type Limiter struct {
	mu            sync.Mutex
	activeIPs     map[string]map[string]int
	oldIPs        map[string]map[string]int
	Nodetype      string         // Node type, e.g. "v2ray", "trojan", "shadowsocks"
	SpeedLimit    int            // Node speed limit in Mbps
	UserOnlineIP  *sync.Map      // Key: TagUUID, value: {Key: Ip, value: Uid}
	UUIDtoUID     map[string]int // Key: UUID, value: Uid
	UserLimitInfo *sync.Map      // Key: TagUUID value: UserLimitInfo
	SpeedLimiter  *sync.Map      // key: TagUUID, value: *DynamicBucket
	aliveList     map[int]int    // Key: Uid, value: alive_ip; protected by mu
}

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
	OverLimit         bool
}

func AddLimiter(nodetype string, tag string, users []panel.UserInfo, aliveList map[int]int) *Limiter {
	l := &Limiter{
		Nodetype:      nodetype,
		UserOnlineIP:  new(sync.Map),
		UserLimitInfo: new(sync.Map),
		SpeedLimiter:  new(sync.Map),
		aliveList:     aliveList,
		activeIPs:     make(map[string]map[string]int),
		oldIPs:        make(map[string]map[string]int),
	}
	uuidmap := make(map[string]int)
	for i := range users {
		uuidmap[users[i].Uuid] = users[i].Id
		userLimit := &UserLimitInfo{}
		userLimit.UID = users[i].Id
		if users[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = users[i].SpeedLimit
		}
		if users[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = users[i].DeviceLimit
		}
		userLimit.OverLimit = false
		l.UserLimitInfo.Store(format.UserTag(tag, users[i].Uuid), userLimit)
	}
	l.UUIDtoUID = uuidmap
	limitLock.Lock()
	limiter[tag] = l
	limitLock.Unlock()
	return l
}

func GetLimiter(tag string) (info *Limiter, err error) {
	limitLock.RLock()
	info, ok := limiter[tag]
	limitLock.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

func DeleteLimiter(tag string) {
	limitLock.Lock()
	delete(limiter, tag)
	limitLock.Unlock()
}

func (l *Limiter) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo, modified []panel.UserInfo) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range deleted {
		key := format.UserTag(tag, deleted[i].Uuid)
		l.UserLimitInfo.Delete(key)
		l.UserOnlineIP.Delete(key)
		l.SpeedLimiter.Delete(key)
		delete(l.activeIPs, key)
		delete(l.oldIPs, key)
		delete(l.UUIDtoUID, deleted[i].Uuid)
		delete(l.aliveList, deleted[i].Id)
	}
	for i := range modified {
		if v, ok := l.UserLimitInfo.Load(format.UserTag(tag, modified[i].Uuid)); ok {
			u := v.(*UserLimitInfo)
			u.SpeedLimit = modified[i].SpeedLimit
			u.DeviceLimit = modified[i].DeviceLimit
			l.UserLimitInfo.Store(format.UserTag(tag, modified[i].Uuid), u)
		}
		limit := int64(determineSpeedLimit(l.SpeedLimit, modified[i].SpeedLimit)) * 1000000 / 8
		if limit > 0 {
			if v, ok := l.SpeedLimiter.Load(format.UserTag(tag, modified[i].Uuid)); ok {
				d := v.(*rate.DynamicBucket)
				d.Update(limit)
			} else {
				d := rate.NewDynamicBucket(limit)
				l.SpeedLimiter.Store(format.UserTag(tag, modified[i].Uuid), d)
			}
		} else {
			l.SpeedLimiter.Delete(format.UserTag(tag, modified[i].Uuid))
		}
	}
	for i := range added {
		userLimit := &UserLimitInfo{
			UID: added[i].Id,
		}
		if added[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = added[i].SpeedLimit
			userLimit.ExpireTime = 0
		}
		if added[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = added[i].DeviceLimit
		}
		userLimit.OverLimit = false
		l.UserLimitInfo.Store(format.UserTag(tag, added[i].Uuid), userLimit)
		l.UUIDtoUID[added[i].Uuid] = added[i].Id
	}
}

func (l *Limiter) UpdateDynamicSpeedLimit(tag, uuid string, limit int, expire time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if v, ok := l.UserLimitInfo.Load(format.UserTag(tag, uuid)); ok {
		info := v.(*UserLimitInfo)
		info.DynamicSpeedLimit = limit
		info.ExpireTime = expire.Unix()
	} else {
		return errors.New("not found")
	}
	return nil
}

func (l *Limiter) SetAliveList(alive map[int]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.aliveList = alive
}

var rejectMissing atomic.Uint64
var rejectDevice atomic.Uint64

func recordReject(reason string, count *atomic.Uint64) {
	n := count.Add(1)
	if n == 1 || n%100 == 0 {
		log.WithFields(log.Fields{"event": "connection_rejected", "reason": reason, "count": n}).Warn("connection rejected")
	}
}

// CheckLimit acquires an active IP reference. The caller must release it when
// its logical link closes, including errors and user revocation.
func (l *Limiter) CheckLimit(taguuid string, ip string, noUDPsource bool) (DynamicBucket *rate.DynamicBucket, release func(), reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// check if ipv4 mapped ipv6
	ip = strings.TrimPrefix(ip, "::ffff:")

	// check and gen speed limit Bucket
	nodeLimit := l.SpeedLimit
	userLimit := 0
	deviceLimit := 0
	var uid int
	if v, ok := l.UserLimitInfo.Load(taguuid); ok {
		u := v.(*UserLimitInfo)
		deviceLimit = u.DeviceLimit
		uid = u.UID
		if u.ExpireTime < time.Now().Unix() && u.ExpireTime != 0 {
			if u.SpeedLimit != 0 {
				userLimit = u.SpeedLimit
				u.DynamicSpeedLimit = 0
				u.ExpireTime = 0
			} else {
				l.UserLimitInfo.Delete(taguuid)
			}
		} else {
			userLimit = determineSpeedLimit(u.SpeedLimit, u.DynamicSpeedLimit)
		}
	} else {
		recordReject("user_missing", &rejectMissing)
		return nil, nil, "user_missing"
	}
	if noUDPsource || l.Nodetype == "hysteria2" || l.Nodetype == "tuic" {
		newipMap := new(sync.Map)
		v, _ := l.UserOnlineIP.LoadOrStore(taguuid, newipMap)
		current := v.(*sync.Map)
		_, currentKnown := current.Load(ip)
		_, oldKnown := l.oldIPs[taguuid][ip]
		known := currentKnown || oldKnown || l.activeIPs[taguuid][ip] > 0
		if !known && deviceLimit > 0 && deviceLimit <= l.aliveList[uid] {
			recordReject("device_limit", &rejectDevice)
			return nil, nil, "device_limit"
		}
		current.Store(ip, uid)
		if l.activeIPs[taguuid] == nil {
			l.activeIPs[taguuid] = make(map[string]int)
		}
		active := l.activeIPs[taguuid]
		active[ip]++
		var once sync.Once
		release = func() {
			once.Do(func() {
				l.mu.Lock()
				defer l.mu.Unlock()
				active[ip]--
				if active[ip] == 0 {
					delete(active, ip)
				}
			})
		}
	}

	limit := int64(determineSpeedLimit(nodeLimit, userLimit)) * 1000000 / 8 // If you need the Speed limit
	if limit > 0 {
		if v, ok := l.SpeedLimiter.Load(taguuid); ok {
			return v.(*rate.DynamicBucket), release, ""
		} else {
			d := rate.NewDynamicBucket(limit)
			l.SpeedLimiter.Store(taguuid, d)
			return d, release, ""
		}
	} else {
		return nil, release, ""
	}
}

func (l *Limiter) GetOnlineDevice() (*[]panel.OnlineUser, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var onlineUser []panel.OnlineUser
	l.oldIPs = make(map[string]map[string]int)
	for key, ips := range l.activeIPs {
		info, ok := l.UserLimitInfo.Load(key)
		if !ok {
			continue
		}
		v, _ := l.UserOnlineIP.LoadOrStore(key, new(sync.Map))
		for ip := range ips {
			v.(*sync.Map).Store(ip, info.(*UserLimitInfo).UID)
		}
	}
	l.UserOnlineIP.Range(func(key, value interface{}) bool {
		taguuid := key.(string)
		ipMap := value.(*sync.Map)
		l.oldIPs[taguuid] = make(map[string]int)
		ipMap.Range(func(key, value interface{}) bool {
			uid := value.(int)
			ip := key.(string)
			l.oldIPs[taguuid][ip] = uid
			onlineUser = append(onlineUser, panel.OnlineUser{UID: uid, IP: ip})
			return true
		})
		l.UserOnlineIP.Delete(taguuid) // Reset online device
		return true
	})

	return &onlineUser, nil
}

type UserIpList struct {
	Uid    int      `json:"Uid"`
	IpList []string `json:"Ips"`
}

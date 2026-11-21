package node

import (
	"context"
	"errors"
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/task"
	vCore "github.com/wyx2685/v2node/core"
)

func (c *Controller) startTasks(node *panel.NodeInfo) {
	// fetch node info task
	c.nodeInfoMonitorPeriodic = &task.Task{
		Name:     "nodeInfoMonitor",
		Interval: node.PullInterval,
		Execute:  c.nodeInfoMonitor,
		ReloadCh: c.server.ReloadCh,
	}
	// fetch user list task
	c.userReportPeriodic = &task.Task{
		Name:     "reportUserTrafficTask",
		Interval: node.PushInterval,
		Execute:  c.reportUserTrafficTask,
		ReloadCh: c.server.ReloadCh,
	}
	log.WithField("tag", c.tag).Info("Start monitor node status")
	// delay to start nodeInfoMonitor
	_ = c.nodeInfoMonitorPeriodic.Start(false)
	log.WithField("tag", c.tag).Info("Start report node status")
	_ = c.userReportPeriodic.Start(false)
	if node.Security == panel.Tls {
		switch c.info.Common.CertInfo.CertMode {
		case "none", "", "file", "self", "remote":
		default:
			c.renewCertPeriodic = &task.Task{
				Name:     "renewCertTask",
				Interval: time.Hour * 24,
				Execute:  c.renewCertTask,
				ReloadCh: c.server.ReloadCh,
			}
			log.WithField("tag", c.tag).Info("Start renew cert")
			// delay to start renewCert
			_ = c.renewCertPeriodic.Start(true)
		}
	}
}

func (c *Controller) nodeInfoMonitor(ctx context.Context) (err error) {
	if c.conf.ConfigToken != "" {
		if err := c.syncManagedConfig(ctx); err != nil {
			log.WithField("tag", c.tag).Warn("Managed config remains unconfirmed: ", err)
		}
	}
	c.applyMu.Lock()
	if c.closed {
		c.applyMu.Unlock()
		return nil
	}
	currentInfo := c.info
	c.applyMu.Unlock()
	// get node info
	var newN *panel.NodeInfo
	if c.conf.ConfigToken == "" {
		newN, err = c.apiClient.GetNodeInfo(ctx)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get node info failed")
		return nil
	}
	if newN != nil && !reflect.DeepEqual(newN, currentInfo) {
		log.WithFields(log.Fields{
			"tag": c.tag,
		}).Error("Got new node info, reload")
		if c.server.ReloadCh != nil {
			select {
			case c.server.ReloadCh <- struct{}{}:
			default:
			}
		} else {
			log.Panic("Reload failed")
		}
	}
	log.WithField("tag", c.tag).Debug("Node info no change")

	// get user info
	newU, err := c.apiClient.GetUserList(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("Get user list failed")
		return nil
	}
	// get user alive
	newA, err := c.apiClient.GetUserAlive(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Warn("Get alive list failed; keeping the previous snapshot")
	}

	// update alive list
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	if c.closed {
		return nil
	}
	if newA != nil {
		c.limiter.SetAliveList(newA)
	}
	// node no changed, check users
	if newU == nil {
		log.WithField("tag", c.tag).Debug("User list no change")
		return nil
	}
	deleted, added, modified := compareUserList(c.userList, newU)
	limiterDeleted := append([]panel.UserInfo(nil), deleted...)
	limiterAdded := append([]panel.UserInfo(nil), added...)
	anyTLS := c.info.Type == "anytls"
	// Reinstall changed users so existing unlimited links cannot survive enrollment.
	for _, u := range modified {
		deleted = append(deleted, u)
		added = append(added, u)
	}
	if anyTLS && len(modified)+len(limiterDeleted) > 0 {
		c.server.SetUserBudgets(c.tag, modified, c.budgets)
		// Publish policy before closing old links so concurrent streams cannot keep old permissions.
		c.limiter.UpdateUser(c.tag, nil, limiterDeleted, modified)
	}
	if len(deleted) > 0 {
		// have deleted users
		err = c.server.DelUsers(deleted, c.tag, c.info)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Delete users failed")
			return nil
		}
	}
	if len(added) > 0 {
		if anyTLS {
			c.server.SetUserBudgets(c.tag, limiterAdded, c.budgets)
			if len(limiterAdded) > 0 {
				// AnyTLS can publish its asynchronous auth batch before AddUsers returns.
				c.limiter.UpdateUser(c.tag, limiterAdded, nil, nil)
			}
		} else {
			c.server.SetUserBudgets(c.tag, added, c.budgets)
		}
		// have added users
		_, err = c.server.AddUsers(&vCore.AddUsersParams{
			Tag:      c.tag,
			NodeInfo: c.info,
			Users:    added,
		})
		if err != nil {
			if anyTLS && len(limiterAdded) > 0 {
				// A partially published auth batch must not admit users from a failed update.
				c.limiter.UpdateUser(c.tag, nil, limiterAdded, nil)
			}
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Add users failed")
			return nil
		}
	}
	if !anyTLS && (len(added) > 0 || len(deleted) > 0) {
		// update Limiter
		c.limiter.UpdateUser(c.tag, limiterAdded, limiterDeleted, modified)
	}
	c.userList = newU
	c.apiClient.ConfirmUserList()
	log.WithField("tag", c.tag).Infof("%d user deleted, %d user added, %d user modified", len(deleted), len(added), len(modified))
	return nil
}

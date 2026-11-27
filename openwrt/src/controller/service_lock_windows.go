package main

import "errors"

func (c *controller) serviceLockAction(action string) error {
	return errors.New("service locking is Linux/OpenWrt only; Windows runs offline tests")
}

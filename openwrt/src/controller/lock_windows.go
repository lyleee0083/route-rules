package main

import "errors"

func lockFile(path string) (func(), error) {
	return nil, errors.New("activation is Linux/OpenWrt only; Windows runs offline tests")
}

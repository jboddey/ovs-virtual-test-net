#!/usr/bin/env python3

import json
import os
import sys
import logger

LOGGER = logger.get_logger('config')
CONFIG_FILE = "config/system.json"

class Config:

    def __init__(self):
        self.config = {}
        LOGGER.info("Loading configuration from %s", CONFIG_FILE)
        self._load_config(CONFIG_FILE)
        
    def _load_config(self, file_name):
        data = self.get_json_data(file_name)
        for key in data:
            self.set(key, data[key])
            
    def get(self, key):
        return self.config[key]
        
    def set(self, key, value):
        self.config[key] = value
        
    def get_json_data(self, json_file):
        with open(json_file, 'r') as f:
            data = json.load(f)
            return data

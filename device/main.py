import ujson
import utime
import os

from third_party import ota_updater


def download_and_install_update_if_available(config_data):
    o = ota_updater.OTAUpdater(github_repo=config_data['ota_config']['repo_url'], 
                                          main_repo_dir=config_data['ota_config']['repo_path'],
                                          main_dir='/',
                                          headers={'Authorization': 'token {}'.format(config_data['ota_config']['repo_token'])})
    o.download_and_install_update_if_available(config_data['wifi_config']['ssid'], config_data['wifi_config']['password'])

def start(config_data):
    from device import Device
    d = Device.get_instance(config_data)
    d.loop()

if __name__ == "__main__":
    f = open('config.json')
    config_data = ujson.load(f)

    if ota_updater.OTAUpdater.get_check_update():
        download_and_install_update_if_available(config_data)

    start(config_data)

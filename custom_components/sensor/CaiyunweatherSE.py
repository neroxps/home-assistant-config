"""
Support for caiyun weather
For more details about this platform, please refer to the documentation at
https://bbs.hassbian.com/thread-1003-1-1.html
"""
import logging
import asyncio
from homeassistant.const import (
     CONF_NAME, ATTR_ATTRIBUTION, CONF_ID
    )
import voluptuous as vol
from datetime import datetime,timedelta
import datetime
from homeassistant.const import (
    CONF_API_KEY, CONF_NAME, CONF_MONITORED_CONDITIONS, ATTR_ATTRIBUTION,CONF_ENTITY_ID)
from homeassistant.const import (
    CONF_ZONE, CONF_DEVICES)
from homeassistant.const import TEMP_CELSIUS ,CONF_LATITUDE, CONF_LONGITUDE
from homeassistant.helpers.entity import Entity
from homeassistant.components.sensor import PLATFORM_SCHEMA
import homeassistant.helpers.config_validation as cv
from homeassistant.util import Throttle
from homeassistant.const import (
    CONF_MONITORED_CONDITIONS)
import requests
import os
import json
import time
from homeassistant.helpers.entity import generate_entity_id
import os
import re
import threading
from homeassistant.util import sanitize_filename
from homeassistant.components import zone
from homeassistant.components.weather import (
    WeatherEntity, ATTR_FORECAST_TEMP, ATTR_FORECAST_TIME)
from homeassistant.const import (TEMP_CELSIUS, TEMP_FAHRENHEIT)



_Log=logging.getLogger(__name__)
CONF_ENTITY_ID = 'entity_id'
CONF_REALTIME = 'realtime'
CONF_PRECIPITATION = 'precipitation'
CONF_HOURLY = 'hourly'
CONF_MINUTELY = 'minutely'
CONF_DAILY = 'daily'
CONF_DAY = 'day'
CONF_ALARM = 'alarm'
CONF_UI = 'ui'
CONF_UI_DEVICES = 'ui_devices'
CONF_ALERT = 'alert'

DOMAIN = 'sensor'

ATTR_URL = 'url'
ATTR_FILENAME = 'filename'

CONDITION_CLASSES = {
    'CLEAR_DAY':'sunny',
    'CLEAR_NIGHT':'sunny',
    'PARTLY_CLOUDY_DAY':'cloudy',
    'PARTLY_CLOUDY_NIGHT':'cloudy',
    'CLOUDY':'cloudy',
    'RAIN':'rainy',
    'SNOW':'snowy',
    'WIND':'windy',
    'FOG':'fog',
    'HAZE':'fog',

}

REALTIME_TYPES = {
    'temperature': ['temperature', '°C','mdi:thermometer'],
    'skycon': ['skycon', None,None],
    'cloudrate': ['cloudrate', '%','mdi:weather-partlycloudy'],
    'aqi': ['AQI', ' ','mdi:cloud-outline'],
    'humidity': ['humidity', '%','mdi:water-percent'],
    'pm25': ['pm25', 'μg/m3','mdi:blur'],
    'o3': ['o3', 'μg/m3','mdi:blur'],
    'co': ['co', 'μg/m3','mdi:blur'],
    'pm10': ['pm10', 'μg/m3','mdi:blur'],
    'no2': ['no2', 'μg/m3','mdi:blur'],
    'pres': ['pres', 'Pa','mdi:arrow-collapse-down'],
    'so2': ['so2', 'μg/m3','mdi:blur'],

}
PRECIPITATION_TYPE = {
    'nearest_precipitation_distance': ['distance', 'km','mdi:near-me'],
    'nearest_precipitation_intensity': ['intensity','mm','mdi:weather-pouring'],
    'local_precipitation_intensity': ['intensity','mm','mdi:weather-pouring'],
    'local_datasource': ['datasource',None,'mdi:database'],
    'wind_direction': ['direction',None,'mdi:compass'],
    'wind_speed': ['speed','Km/h','mdi:weather-windy'],
}
HOURLY_TYPE = {
    'description':['description', None,'mdi:cloud-print-outline'],
    'skycon': ['skycon', None,None],
    'cloudrate': ['cloudrate', '%','mdi:weather-partlycloudy'],
    'aqi': ['AQI', ' ','mdi:cloud-outline'],
    'humidity': ['humidity', '%','mdi:water-percent'],
    'pm25': ['pm25', 'μg/m3','mdi:blur'],
    'precipitation': ['precipitation', 'mm','mdi:weather-rainy'],
    'wind': ['speed','Km/h','mdi:weather-windy'],
    'temperature': ['temperature', '°C','mdi:thermometer'],
    'precipitation8h': ['precipitation8h', 'mm','mdi:weather-rainy'],
}
MINUTELY_TYPE = {
    'description':['description', None,'mdi:cloud-print-outline'],
    'probability_0':['probability' ,'%','mdi:weather-pouring'],
    'probability_1':['probability' ,'%','mdi:weather-pouring'],
    'probability_2':['probability' ,'%','mdi:weather-pouring'],
    'probability_3':['probability' ,'%','mdi:weather-pouring'],
    'probability_4':['probability' ,'%','mdi:weather-pouring'],
    'probability_5':['probability' ,'%','mdi:weather-pouring'],
    'precipitation_2h':['precipitation_2h' ,'mm','mdi:weather-rainy'],
    'precipitation':['precipitation' ,'mm','mdi:weather-rainy'],
}

DAILY_TYPE = {
    'coldRisk': ['desc',None,'mdi:hospital'],
    'temperature_max' :['max','°C','mdi:thermometer'],
    'temperature_avg': ['avg','°C','mdi:thermometer'],
    'temperature_min': ['min','°C','mdi:thermometer'],
    'skycon': ['skycon', None,None],
    'cloudrate_max': ['max', '%','mdi:weather-partlycloudy'],
    'cloudrate_avg': ['avg', '%','mdi:weather-partlycloudy'],
    'cloudrate_min': ['min', '%','mdi:weather-partlycloudy'],
    'aqi_max': ['max', ' ','mdi:cloud-outline'],
    'aqi_avg': ['avg', ' ','mdi:cloud-outline'],
    'aqi_min': ['min', ' ','mdi:cloud-outline'],
    'humidity_max': ['max', '%','mdi:water-percent'],
    'humidity_avg': ['avg', '%','mdi:water-percent'],
    'humidity_min': ['min', '%','mdi:water-percent'],
    'sunset':['sunset',None,'mdi:weather-sunset-down'],
    'sunrise':['sunrise',None,'mdi:weather-sunset-up'],
    'ultraviolet':['ultraviolet',None,'mdi:umbrella'],
    'pm25_max': ['max', 'μg/m3','mdi:blur'],
    'pm25_avg': ['avg', 'μg/m3','mdi:blur'],
    'pm25_min': ['min', 'μg/m3','mdi:blur'],
    'dressing':['desc',None,'mdi:tshirt-crew'],
    'carWashing':['carWashing',None,'mdi:car'],
    'precipitation_max' : ['max','mm','mdi:weather-rainy'],
    'precipitation_avg': ['avg','mm','mdi:weather-rainy'],
    'precipitation_min': ['min','mm','mdi:weather-rainy'],
    'wind_max': ['max', 'Km/h','mdi:weather-windy'],
    'wind_avg': ['avg', 'Km/h','mdi:weather-windy'],
    'wind_min': ['min', 'Km/h','mdi:weather-windy'],
    'wind_direction_max': ['direction',None,'mdi:compass'],
    'wind_direction_avg': ['direction',None,'mdi:compass'],
    'wind_direction_min': ['direction',None,'mdi:compass'],

}
DAY_TYPE = {
    'day1':['day1','unit','icon'],
    'day2':['day2','unit','icon'],
    'day3':['day3','unit','icon'],
    'day4':['day4','unit','icon'],
}
ALARM_TYPE = {
    'rainstorm':['rainstorm','mm','mdi:weather-rainy'],
    'precipitation':['precipitation','mm','mdi:weather-rainy'],
    'typhoon':['typhoon','Km/h','mdi:weather-windy'],
    'high_temp':['high_temp','°C','mdi:thermometer'],
    'low_temp':['low_temp','°C','mdi:thermometer'],
    'aqi':['aqi', ' ','mdi:cloud-outline'],
    'pm25':['pm25','μg/m3','mdi:blur'],
}
SKYCON_ICON = {
    '晴天':'mdi:weather-sunny',
    '晴夜':'mdi:weather-night',
    '多云':'mdi:weather-cloudy',
    '阴':'mdi:weather-cloudy',
    '雨':'mdi:weather-pouring',
    '雪':'mdi:weather-snowy',
    '风':'mdi:weather-windy',
    '雾':'mdi:weather-fog',
    '雾霾':'mdi:weather-fog',
}
SKYCON_TYPE = {
    'CLEAR_DAY':'晴天',
    'CLEAR_NIGHT':'晴夜',
    'PARTLY_CLOUDY_DAY':'多云',
    'PARTLY_CLOUDY_NIGHT':'多云',
    'CLOUDY':'阴',
    'RAIN':'雨',
    'SNOW':'雪',
    'WIND':'风',
    'FOG':'雾',
    'HAZE':'雾霾',
}
num_day_type = {
    0:'今天',
    1:'明天',
    2:'后天',
    3:(datetime.datetime.now() + datetime.timedelta(days = 3)).strftime('%Y-%m-%d'),
    4:(datetime.datetime.now() + datetime.timedelta(days = 4)).strftime('%Y-%m-%d'),
    }


MODULE_SCHEMA = vol.Schema({
    vol.Required(CONF_REALTIME,default=[]):vol.All(cv.ensure_list,[vol.In(REALTIME_TYPES)]),
    vol.Required(CONF_PRECIPITATION,default=[]):vol.All(cv.ensure_list,[vol.In(PRECIPITATION_TYPE)]),
    vol.Required(CONF_HOURLY,default=[]):vol.All(cv.ensure_list,[vol.In(HOURLY_TYPE)]),
    vol.Required(CONF_MINUTELY,default=[]):vol.All(cv.ensure_list,[vol.In(MINUTELY_TYPE)]),
    vol.Required(CONF_DAILY,default=[]):vol.All(cv.ensure_list,[vol.In(DAILY_TYPE)]),
    vol.Optional(CONF_DAY,default=[]):vol.All(cv.ensure_list,[vol.In(DAY_TYPE)]),
    vol.Optional(CONF_ALARM,default=[]):vol.All(cv.ensure_list,[vol.In(ALARM_TYPE)]),
})
PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_NAME): cv.string,
    vol.Optional(CONF_MONITORED_CONDITIONS): MODULE_SCHEMA,
    vol.Optional(CONF_DEVICES, default=[]):
        vol.All(cv.ensure_list, [cv.entity_id]),
    vol.Required(CONF_API_KEY): cv.string,
    vol.Optional(CONF_UI, default=False): cv.boolean,
    vol.Optional(CONF_UI_DEVICES, default=[]):
        vol.All(cv.ensure_list, [cv.entity_id]),
    vol.Optional(CONF_ALERT, default=False): cv.boolean,

})

def setup_platform(hass, config, add_devices, discovery_info=None):
    """Setup the sensor platform."""

    sensor_name = config.get(CONF_NAME)

    api_key = config.get(CONF_API_KEY,None)
    if api_key == None:
        _Log.error('Pls enter api_key!')
        return False

    #获取天气污染预警参数
    alert = config.get(CONF_ALERT)


    latitude = hass.config.latitude
    longitude = hass.config.longitude
    monitored_conditions = config[CONF_MONITORED_CONDITIONS]

    download_path = os.path.join(hass.config.path('downloads'))
    if not os.path.isdir(download_path):
        _LOGGER.error(
            "Download path %s does not exist. File Downloader not active",
            download_path)

        return False
    def download_json(url,filename):
        hass.services.call('downloader', 'download_file', {
            'url': url,
            'filename': filename,
            'overwrite': 'yes',
        })

    def download_file(service):
        url = service.data[ATTR_URL]
        filename = service.data[ATTR_FILENAME]
        def do_download():
            download_json(url,filename)
        threading.Thread(target=do_download).start()


    #home_latitude = home_tracker_state.attributes.get('latitude')
    #home_longitude = home_tracker_state.attributes.get('longitude'
    dev = []
    if  CONF_REALTIME in monitored_conditions:
        realtimeSensor = monitored_conditions['realtime']
        if isinstance(realtimeSensor, list):
            if len(realtimeSensor) == 0:
                sensor_name = REALTIME_TYPES['temperature'][0]
                measurement =  REALTIME_TYPES['temperature'][1]
                icon = REALTIME_TYPES['temperature'][2]
                dev.append(CaiyunSensor(CONF_REALTIME, 'temperature', sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))
            for sensor in realtimeSensor:
                sensor_name = REALTIME_TYPES[sensor][0]
                measurement = REALTIME_TYPES[sensor][1]
                icon = REALTIME_TYPES[sensor][2]
                dev.append(CaiyunSensor(CONF_REALTIME, sensor, sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))
    if  CONF_PRECIPITATION in monitored_conditions:
        precipitationSensor = monitored_conditions['precipitation']
        if isinstance(precipitationSensor, list):
            if len(precipitationSensor) == 0:
                sensor_name = PRECIPITATION_TYPE['nearest_precipitation_distance'][0]
                measurement =  PRECIPITATION_TYPE['nearest_precipitation_distance'][1]
                icon =  PRECIPITATION_TYPE['nearest_precipitation_distance'][2]
                dev.append(CaiyunSensor(CONF_PRECIPITATION, 'nearest_precipitation_distance', sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))
            for sensor in precipitationSensor:
                sensor_name = PRECIPITATION_TYPE[sensor][0]
                measurement = PRECIPITATION_TYPE[sensor][1]
                icon =  PRECIPITATION_TYPE[sensor][2]
                dev.append(CaiyunSensor(CONF_PRECIPITATION, sensor, sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))

    if  CONF_HOURLY in monitored_conditions:
        hourlySensor = monitored_conditions['hourly']
        if isinstance(hourlySensor, list):
            if len(hourlySensor) == 0:
                sensor_name = HOURLY_TYPE['description'][0]
                measurement =  HOURLY_TYPE['description'][1]
                icon =  HOURLY_TYPE['description'][2]
                dev.append(CaiyunSensor(CONF_HOURLY, 'description', sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))
            for sensor in hourlySensor:
                sensor_name = HOURLY_TYPE[sensor][0]
                measurement = HOURLY_TYPE[sensor][1]
                icon =  HOURLY_TYPE[sensor][2]
                dev.append(CaiyunSensor(CONF_HOURLY, sensor, sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))
    if  CONF_MINUTELY in monitored_conditions:
        minutelySensor = monitored_conditions['minutely']
        if isinstance(minutelySensor, list):
            if len(minutelySensor) == 0:
                sensor_name = MINUTELY_TYPE['description'][0]
                measurement =  MINUTELY_TYPE['description'][1]
                icon =  MINUTELY_TYPE['description'][2]
                dev.append(CaiyunSensor(CONF_MINUTELY, 'description', sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))
            for sensor in minutelySensor:
                sensor_name = MINUTELY_TYPE[sensor][0]
                measurement = MINUTELY_TYPE[sensor][1]
                icon =  MINUTELY_TYPE[sensor][2]
                dev.append(CaiyunSensor(CONF_MINUTELY, sensor, sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))

    if  CONF_DAILY in monitored_conditions:
        dailySensor = monitored_conditions['daily']
        if isinstance(dailySensor, list):
            if len(dailySensor) == 0:
                sensor_name = DAILY_TYPE['coldRisk'][0]
                measurement =  DAILY_TYPE['coldRisk'][1]
                icon =  DAILY_TYPE['coldRisk'][2]
                dev.append(CaiyunSensor(CONF_DAILY, 'coldRisk', sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))
            for sensor in dailySensor:
                sensor_name = DAILY_TYPE[sensor][0]
                measurement = DAILY_TYPE[sensor][1]
                icon = DAILY_TYPE[sensor][2]
                dev.append(CaiyunSensor(CONF_DAILY, sensor, sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))
    if CONF_ALARM in monitored_conditions:
        alarmSensor = monitored_conditions['alarm']
        if isinstance(alarmSensor,list):
            for sensor in alarmSensor:
                sensor_name = ALARM_TYPE[sensor][0]
                measurement = ALARM_TYPE[sensor][1]
                icon = ALARM_TYPE[sensor][2]
                dev.append(CaiyunSensor(CONF_ALARM,  sensor, sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))
    if  CONF_DAY in monitored_conditions:
        daySensor = monitored_conditions['day']
        if isinstance(daySensor, list):
            for day in daySensor:
                for sensor in dailySensor:
                    sensor_name = DAY_TYPE[day][0]+DAILY_TYPE[sensor][0]
                    measurement = DAILY_TYPE[sensor][1]
                    icon = DAILY_TYPE[sensor][2]
                    dev.append(CaiyunSensor(DAY_TYPE[day][0], sensor, sensor_name,measurement,icon,api_key,None, hass, None, download_path, None))
    dev.append(CaiyunSensor('realtime_update', 'realtime_update', 'realtime_update_time',None,'mdi:clock',api_key, None, hass, download_file, download_path, alert))
    dev.append(CaiyunSensor('forecast_update', 'forecast_update', 'forecast_update_time',None,'mdi:clock',api_key, None, hass, download_file, download_path, alert))
    dev.append(CaiyunSensor('alert', 'alert', 'weather_alert',None,'mdi:alarm-light',api_key, None, hass, None, download_path, None))
    add_devices(dev,True)
    entity_id = config.get(CONF_DEVICES)
    dev0 = []
    for i in range(len(entity_id)):
        dev0.append(CaiyunSensor(CONF_MINUTELY, 'tracker', entity_id[i]+'_description', None, 'mdi:heart-half-full', api_key, entity_id[i], hass, download_file, download_path, alert))
    add_devices(dev0,True)

    #添加主天气温度曲线图
    ui = config.get(CONF_UI)

    if ui == True:
        forecastjson_path=os.path.join(download_path, 'forecast.json')
        add_devices([CaiyunWeatherUI(hass,forecastjson_path,'disable')])

    #添加异地天气温度曲线图
    ui_devices = config.get(CONF_UI_DEVICES)
    dev1 = []
    for i in range(len(ui_devices)):
        if ui_devices[i] in entity_id:
            ui_fore_filename = ui_devices[i].replace('.','_')+'_forecast.json'
            forecastjson_path=os.path.join(download_path, ui_fore_filename)
            dev1.append(CaiyunWeatherUI(hass,forecastjson_path,ui_devices[i]))
    add_devices(dev1,True)



class CaiyunSensor(Entity):
    """Representation of a Sensor."""


    def __init__(self,sensor_Type,sensor,sensor_name,measurement,icon,api_key, entity_id, hass, download_file, download_path, alert):

        self._sensor_Type = sensor_Type
        self._sensor = sensor
        self.attributes = {}

        self._state = None
        self._name = sensor_name
        self.data = None
        self.measurement = measurement
        self.tracker_id = entity_id

        self.api_key = api_key
        self.alert = alert

        self.hass = hass


        self.download_file = download_file
        self.download_path = download_path
        self.longitude = self.hass.config.longitude
        self.latitude = self.hass.config.latitude
        self.forecast_path = os.path.join(self.download_path, 'forecast.json')
        self.realtime_path = os.path.join(self.download_path, 'realtime.json')
        self._icon = icon





        def creat_downdata_service(self,service_name, data_type, file_name,  api_key, longitude, latitude,download_path):
            if self.alert == True:
                download_url = 'https://api.caiyunapp.com/v2/%s/%s,%s/%s?alert=true' % (api_key, longitude, latitude, data_type)
            else:
                download_url = 'https://api.caiyunapp.com/v2/%s/%s,%s/%s' % (api_key, longitude, latitude, data_type)
            self.hass.services.register(DOMAIN, service_name, self.download_file,
                                   schema=vol.Schema({
                                   vol.Required(ATTR_URL,default=download_url):cv.url,
                                   vol.Required(ATTR_FILENAME,default= file_name):cv.string}))
            file_path =  os.path.join(download_path, file_name)
            return file_path



        if self._sensor ==  'realtime_update':
            creat_downdata_service(self,'Download_Caiyun_weatherData_forecast', 'forecast', 'forecast.json', self.api_key, self.longitude, self.latitude,self.download_path)
            creat_downdata_service(self,'Download_Caiyun_weatherData_realtime', 'realtime', 'realtime.json', self.api_key, self.longitude, self.latitude,self.download_path)


        if self._sensor ==  'tracker':
            self.tracker_state = self.hass.states.get(self.tracker_id)

            elatitude = self.tracker_state.attributes.get('latitude')
            elongitude = self.tracker_state.attributes.get('longitude')
            self.entity_id = generate_entity_id(
                'sensor.{}', sensor_name, hass=self.hass)
            remove_dot_tracker_id = ''
            if '.' in self.tracker_id:
                self.entityid_filepath = creat_downdata_service(self,'Download_Caiyun_'+self.tracker_id.replace('.','_') +'_forecast', 'forecast', self.tracker_id.replace('.','_') +'_forecast.json', self.api_key, elongitude, elatitude,self.download_path)
            #self.entityid_filepath = os.path.join(self.download_path, self.tracker_id +'_forecast.json')






    def get_entityid_data(self,entityid_filepath):
        try:
            with open(entityid_filepath, 'r', encoding='utf-8') as file_data:
                entityid_forecast_data = json.load(file_data)

        except (IndexError, FileNotFoundError, IsADirectoryError,
                UnboundLocalError):
            _Log.warning("File or data not present at the moment: %s",
                            os.path.basename(entityid_filepath))
            return
        return entityid_forecast_data

    @property
    def name(self):
        """Return the name of the sensor."""
        if self.tracker_id != None:
            return '彩云异地天气预测'
        else:
            return 'CaiYun' + '_'  + self._sensor_Type + '_' + self._sensor

    @property
    def icon(self):
        """Icon to use in the frontend, if any."""
        return self._icon


    @property
    def state(self):
        """Return the state of the sensor."""
        return self._state

    @property
    def device_state_attributes(self):
        """Return the state attributes."""
        return self.attributes
    @property
    def unit_of_measurement(self):
        """Return the unit this state is expressed in."""
        return self.measurement

    def direction_chinese(self,direction):
        if direction > 337.4 or direction < 22.5:
            final_direction = '北风'
        elif direction > 22.4 and direction < 67.5:
            final_direction = '东北风'
        elif direction > 67.4 and direction < 112.5:
            final_direction = '东风'
        elif direction > 112.4 and direction < 157.5:
            final_direction = '东南风'
        elif direction > 157.4 and direction < 202.5:
            final_direction = '南风'
        elif direction > 202.4 and direction < 247.5:
            final_direction = '西南风'
        elif direction > 247.4 and direction < 292.5:
            final_direction = '西风'
        elif direction > 292.4 and direction < 337.5:
            final_direction = '西北风'
        else:
            final_direction = '无数据'
        return final_direction

    #处理skycon类型返回中文类型
    def skycon_type(self,skycon_type):
        if skycon_type in SKYCON_TYPE.keys():
            return SKYCON_TYPE[skycon_type]
        else:
            return '无数据'

    def get_daily(self,num):
        if self._sensor ==  'coldRisk':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['coldRisk'][num]['desc']
        if self._sensor ==  'temperature_max':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['temperature'][num]['max']
        if self._sensor ==  'temperature_avg':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['temperature'][num]['avg']
        if self._sensor ==  'temperature_min':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['temperature'][num]['min']
        if self._sensor ==  'skycon':
            skycon_type = self.data_forecast['result']['daily']['skycon'][num]['value']
            self._state = self.skycon_type(skycon_type)
            self._icon = SKYCON_ICON[self._state]
        if self._sensor ==  'cloudrate_max':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = int(self.data_forecast ['cloudrate'][num]['max']*100)
        if self._sensor ==  'cloudrate_avg':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = int(self.data_forecast ['cloudrate'][num]['avg']*100)
        if self._sensor ==  'cloudrate_min':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = int(self.data_forecast ['cloudrate'][num]['min'])*100
        if self._sensor ==  'aqi_max':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['aqi'][num]['max']
        if self._sensor ==  'aqi_avg':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['aqi'][num]['avg']
        if self._sensor ==  'aqi_min':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['aqi'][num]['min']
        if self._sensor ==  'humidity_max':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = int(self.data_forecast ['humidity'][num]['max']*100)
        if self._sensor ==  'humidity_avg':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = int(self.data_forecast ['humidity'][num]['avg']*100)
        if self._sensor ==  'humidity_min':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = int(self.data_forecast ['humidity'][num]['min']*100)
        if self._sensor ==  'sunset':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['astro'][num]['sunset']['time']
        if self._sensor ==  'sunrise':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['astro'][num]['sunrise']['time']
        if self._sensor ==  'ultraviolet':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['ultraviolet'][num]['desc']
        if self._sensor ==  'pm25_max':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['pm25'][num]['max']
        if self._sensor ==  'pm25_avg':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['pm25'][num]['avg']
        if self._sensor ==  'pm25_min':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['pm25'][num]['min']
        if self._sensor ==  'dressing':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['dressing'][num]['desc']
        if self._sensor ==  'carWashing':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['carWashing'][num]['desc']
        if self._sensor ==  'precipitation_max':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['precipitation'][num]['max']
        if self._sensor ==  'precipitation_avg':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['precipitation'][num]['avg']
        if self._sensor ==  'precipitation_min':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['precipitation'][num]['min']
        if self._sensor ==  'wind_max':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['wind'][num]['max']['speed']
        if self._sensor ==  'wind_avg':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['wind'][num]['avg']['speed']
        if self._sensor ==  'wind_min':
            self.data_forecast = self.data_forecast['result']['daily']
            self._state = self.data_forecast ['wind'][num]['min']['speed']
        if self._sensor ==  'wind_direction_max':
            direction = self.data_forecast['result']['daily']['wind'][num]['max']['direction']
            self._state = self.direction_chinese(direction)
        if self._sensor ==  'wind_direction_avg':
            direction = self.data_forecast['result']['daily']['wind'][num]['avg']['direction']
            self._state = self.direction_chinese(direction)
        if self._sensor ==  'wind_direction_min':
            direction = self.data_forecast['result']['daily']['wind'][num]['min']['direction']
            self._state = self.direction_chinese(direction)

    def update(self):
        """Fetch new state data for the sensor.

        This is the only method that should fetch new data for Home Assistant.
        """
        realtime_file_path = self.realtime_path
        try:
            with open(realtime_file_path, 'r', encoding='utf-8') as file_data:
                realtime_data = json.load(file_data)

        except (IndexError, FileNotFoundError, IsADirectoryError,
                UnboundLocalError):
            _Log.warning("File or data not present at the moment: %s",
                            os.path.basename(realtime_file_path))
            return

        self.data_currently = realtime_data
        if self._sensor_Type == 'realtime_update':
            realupdate_time = time.localtime(self.data_currently['server_time'])
            self._state = time.strftime('%Y-%m-%d %H:%M:%S',realupdate_time)
        if not 'result' in self.data_currently:
            _Log.error('Json Status Error1!')
            return
        if self._sensor_Type == CONF_REALTIME:
            if self._sensor ==  'skycon':
                skycon_type = self.data_currently['result']['skycon']
                self._state = self.skycon_type(skycon_type)
                self._icon = SKYCON_ICON[self._state]
            elif self._sensor == 'cloudrate':
                self._state = self.data_currently['result']['cloudrate']*100
            elif self._sensor == 'humidity':
                self._state = round(self.data_currently['result']['humidity']*100,2)
            else:
                self.data_currently = self.data_currently['result']
                if self._sensor not in self.data_currently:
                    self._state = "您的API_KEY不支持该参数:"+str(self._sensor)
                else:
                    self._state = self.data_currently [self._sensor]

        if self._sensor_Type == CONF_PRECIPITATION:
            if self._sensor ==  'nearest_precipitation_distance':
                self.data_currently = self.data_currently['result']['precipitation']['nearest']
                self._state = self.data_currently ['distance']
            if self._sensor ==  'nearest_precipitation_intensity':
                self.data_currently = self.data_currently['result']['precipitation']['nearest']
                self._state = self.data_currently ['intensity']
            if self._sensor ==  'local_precipitation_intensity':
                self.data_currently = self.data_currently['result']['precipitation']['local']
                self._state = self.data_currently ['intensity']
            if self._sensor ==  'local_datasource':
                self.data_currently = self.data_currently['result']['precipitation']['local']
                self._state = self.data_currently ['datasource']
            if self._sensor ==  'wind_direction':
                direction = self.data_currently['result']['wind']['direction']
                self._state = self.direction_chinese(direction)
            if self._sensor ==  'wind_speed':
                self.data_currently = self.data_currently['result']['wind']
                self._state = self.data_currently ['speed']
        forecast_file_path = self.forecast_path
        try:
            with open(forecast_file_path, 'r', encoding='utf-8') as file_data:
                forecast_data = json.load(file_data)

        except (IndexError, FileNotFoundError, IsADirectoryError,
                UnboundLocalError):
            _Log.warning("File or data not present at the moment: %s",
                            os.path.basename(forecast_file_path))
            return


        self.data_forecast = forecast_data
        if not 'result' in self.data_forecast:
            _Log.error('Json Status Error1!')
            return
        if self._sensor_Type == 'forecast_update':
            self._state = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(self.data_forecast['server_time']))

        if self._sensor_Type == 'alert':
            if 'alert' not in self.data_forecast['result']:
                self._state = '您的API_KEY不支持该参数[alert:True]'
            elif self.data_forecast['result']['alert']['content'] == []:
                self._state = '无污染预警'
            elif 'description' in self.data_forecast['result']['alert']['content'][0]:
                self._state = self.data_forecast['result']['alert']['content'][0]['description']
                self.attributes['发布时间'] = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(self.data_forecast['result']['alert']['content'][0]['pubtimestamp']))


        if self._sensor_Type == CONF_HOURLY:
            if self._sensor ==  'description':
                self._state = self.data_forecast['result']['hourly']['description']
            if self._sensor ==  'skycon':
                skycon_type = self.data_forecast['result']['hourly']['skycon'][1]['value']
                self._state = self.skycon_type(skycon_type)
                self._icon = SKYCON_ICON[self._state]



            if self._sensor ==  'cloudrate':
                self.data_forecast = self.data_forecast['result']['hourly']
                self._state = int(self.data_forecast ['cloudrate'][0]['value']*100)
                add_cloudrate_data = {}
                for i in range(47,-1,-1):
                    cloudrate_data = {self.data_forecast ['cloudrate'][i]['datetime']:int(self.data_forecast ['cloudrate'][i]['value']*100)}
                    add_cloudrate_data = dict(cloudrate_data, **add_cloudrate_data)
                self.attributes = add_cloudrate_data
            if self._sensor ==  'aqi':
                self.data_forecast = self.data_forecast['result']['hourly']
                self._state = self.data_forecast ['aqi'][0]['value']
                add_aqi_data = {}
                for i in range(47,-1,-1):
                    aqi_data = {self.data_forecast ['aqi'][i]['datetime']:self.data_forecast ['aqi'][i]['value']}
                    add_aqi_data = dict(aqi_data, **add_aqi_data)
                self.attributes = add_aqi_data
            if self._sensor ==  'humidity':
                self.data_forecast = self.data_forecast['result']['hourly']
                self._state = int(self.data_forecast ['humidity'][0]['value']*100)
                add_humidity_data = {}
                for i in range(47,-1,-1):
                    humidity_data = {self.data_forecast ['humidity'][i]['datetime']:int(self.data_forecast ['humidity'][i]['value']*100)}
                    add_humidity_data = dict(humidity_data, **add_humidity_data)
                self.attributes = add_humidity_data

            if self._sensor ==  'pm25':
                self.data_forecast = self.data_forecast['result']['hourly']
                self._state = self.data_forecast ['pm25'][0]['value']
                add_pm25_data = {}
                for i in range(47,-1,-1):
                    pm25_data = {self.data_forecast ['pm25'][i]['datetime']:self.data_forecast ['pm25'][i]['value']}
                    add_pm25_data = dict(pm25_data, **add_pm25_data)
                self.attributes = add_pm25_data
            if self._sensor ==  'precipitation':
                self.data_forecast = self.data_forecast['result']['hourly']
                self._state = self.data_forecast ['precipitation'][0]['value']
                add_prec_data = {}
                for i in range(47,-1,-1):
                    if self.data_forecast ['precipitation'][i]['datetime'][0:10] ==  datetime.datetime.now().strftime('%Y-%m-%d'):
                        prec_data = {'今天'+self.data_forecast ['precipitation'][i]['datetime'][-5:]:self.data_forecast ['precipitation'][i]['value']}
                        add_prec_data = dict(prec_data, **add_prec_data)
                    elif self.data_forecast ['precipitation'][i]['datetime'][0:10] ==  (datetime.datetime.now() + datetime.timedelta(days = 1)).strftime('%Y-%m-%d'):
                        prec_data = {'明天'+self.data_forecast ['precipitation'][i]['datetime'][-5:]:self.data_forecast ['precipitation'][i]['value']}
                        add_prec_data = dict(prec_data, **add_prec_data)
                    elif self.data_forecast ['precipitation'][i]['datetime'][0:10] ==  (datetime.datetime.now() + datetime.timedelta(days = 2)).strftime('%Y-%m-%d'):
                        prec_data = {'后天'+self.data_forecast ['precipitation'][i]['datetime'][-5:]:self.data_forecast ['precipitation'][i]['value']}
                        add_prec_data = dict(prec_data, **add_prec_data)
                    else:
                        prec_data = {self.data_forecast ['precipitation'][i]['datetime']:self.data_forecast ['precipitation'][i]['value']}
                        add_prec_data = dict(prec_data, **add_prec_data)
                self.attributes = add_prec_data
            #precipitation8h，8小时降雨预测 0.05 ~ 0.9 小雨 0.9 ~ 2.87 中雨 >2.87大雨
            if self._sensor ==  'precipitation8h':
                self.data_forecast = self.data_forecast['result']['hourly']
                add_prec8h_data = {}
                for i in range(7,-1,-1):
                    prec8h_data = {self.data_forecast ['precipitation'][i]['datetime']:self.data_forecast ['precipitation'][i]['value']}
                    add_prec8h_data = dict(prec8h_data, **add_prec8h_data)
                self.attributes = add_prec8h_data
                self._state = max(add_prec8h_data.values())


            if self._sensor ==  'wind':
                self.data_forecast = self.data_forecast['result']['hourly']
                self._state = self.data_forecast ['wind'][0]['speed']
                add_wind_data = {}
                for i in range(47,-1,-1):
                    wind_data = {self.data_forecast ['wind'][i]['datetime']:self.data_forecast ['wind'][i]['speed']}
                    add_wind_data = dict(wind_data, **add_wind_data)
                self.attributes = add_wind_data
            if self._sensor ==  'temperature':
                self.data_forecast = self.data_forecast['result']['hourly']
                self._state = self.data_forecast ['temperature'][0]['value']
                add_temp_data = {}
                for i in range(47,-1,-1):
                    temp_data = {self.data_forecast ['temperature'][i]['datetime']:self.data_forecast ['temperature'][i]['value']}
                    add_temp_data = dict(temp_data, **add_temp_data)
                self.attributes = add_temp_data

        if self._sensor_Type == CONF_MINUTELY:
            if self._sensor == 'tracker':
                add_prec8h_data = {}
                for i in range(7,-1,-1):
                    prec8h_data = {str(i):self.get_entityid_data(self.entityid_filepath) ['result']['hourly']['precipitation'][i]['value']}
                    add_prec8h_data = dict(prec8h_data, **add_prec8h_data)
                max_8h_prec = max(add_prec8h_data.values())
                adddict = {
                '分钟级天气概况':self.get_entityid_data(self.entityid_filepath) ['result']['minutely']['description'],
                '小时级天气概况':self.get_entityid_data(self.entityid_filepath)['result']['hourly']['description'],
                '空气质量指数':self.get_entityid_data(self.entityid_filepath)['result']['hourly']['aqi'][0]['value'],
                'PM2.5':self.get_entityid_data(self.entityid_filepath)['result']['hourly']['pm25'][0]['value'],
                '温度':self.get_entityid_data(self.entityid_filepath)['result']['hourly']['temperature'][0]['value'],
                '湿度': self.get_entityid_data(self.entityid_filepath)['result']['hourly']['humidity'][0]['value'],
                '降雨量':self.get_entityid_data(self.entityid_filepath)['result']['hourly']['precipitation'][0]['value'],
                '风速':self.get_entityid_data(self.entityid_filepath)['result']['hourly']['wind'][0]['speed'],
                '风向':self.direction_chinese(self.get_entityid_data(self.entityid_filepath)['result']['hourly']['wind'][0]['direction']),
                '30分钟内降雨概率':self.get_entityid_data(self.entityid_filepath)['result']['minutely']['probability'][0],
                '8小时最大降雨量':max_8h_prec,
                }
                #dictMerged2=dict(self.tracker_state.attributes, **adddict)
                self.attributes = adddict
                self._state = self.get_entityid_data(self.entityid_filepath)['result']['hourly']['precipitation'][0]['value']
                self.measurement = 'mm'
            if self._sensor ==  'description':
                self.data_forecast = self.data_forecast['result']['minutely']
                self._state = self.data_forecast ['description']
            if self._sensor ==  'probability_0':
                self.data_forecast = self.data_forecast['result']['minutely']['probability']
                self._state = round(self.data_forecast [0]*100,2)
            if self._sensor ==  'probability_1':
                self.data_forecast = self.data_forecast['result']['minutely']['probability']
                self._state = round(self.data_forecast [1]*100,2)
            if self._sensor ==  'probability_2':
                self.data_forecast = self.data_forecast['result']['minutely']['probability']
                self._state = round(self.data_forecast [2]*100,2)
            if self._sensor ==  'probability_3':
                self.data_forecast = self.data_forecast['result']['minutely']['probability']
                self._state = round(self.data_forecast [3]*100,2)
            if self._sensor ==  'probability_4':
                if 'probability_4h' in self.data_forecast['result']['minutely']:
                    self.data_forecast = self.data_forecast['result']['minutely']['probability_4h']
                    self._state = round(self.data_forecast [2]*100,2)
                else:
                    self._state = '您的API_KEY不支持该参数[probability_4]'

            if self._sensor ==  'probability_5':
                if 'probability_4h' in self.data_forecast['result']['minutely']:
                    self.data_forecast = self.data_forecast['result']['minutely']['probability_4h']
                    self._state = round(self.data_forecast [3]*100,2)
                else:
                    self._state = '您的API_KEY不支持该参数[probability_5]'

            if self._sensor == 'precipitation_2h':
                self.data_forecast = self.data_forecast['result']['minutely']['precipitation_2h']

                add_p2h_data = {}
                for i in range(119,-1,-1):
                    p2h_data = {'第'+str(i+1)+'分钟':self.data_forecast[i]}
                    add_p2h_data = dict(p2h_data, **add_p2h_data)
                self.attributes = add_p2h_data
                self._state = max(add_p2h_data.values())
            if self._sensor == 'precipitation':
                self.data_forecast = self.data_forecast['result']['minutely']['precipitation']

                add_p1h_data = {}
                for i in range(59,-1,-1):
                    p1h_data = {'第'+str(i+1)+'分钟':self.data_forecast[i]}
                    add_p1h_data = dict(p1h_data, **add_p1h_data)
                self.attributes = add_p1h_data
                self._state = max(add_p1h_data.values())


        if self._sensor_Type == CONF_DAILY:
            self.get_daily(0)
        if self._sensor_Type == 'day1':
            self.get_daily(1)
        if self._sensor_Type == 'day2':
            self.get_daily(2)
        if self._sensor_Type == 'day3':
            self.get_daily(3)
        if self._sensor_Type == 'day4':
            self.get_daily(4)

        #alarm Sensor预警传感器
        if self._sensor_Type == CONF_ALARM:
            if self._sensor ==  'rainstorm':
                self.data_forecast = self.data_forecast['result']['hourly']

                add_prec12h = 0
                add_prec3h = 0
                add_prec6h = 0
                for i in range(11,-1,-1):
                    prec_value = float(self.data_forecast ['precipitation'][i]['value'])
                    add_prec12h = add_prec12h + prec_value

                for i in range(5,-1,-1):
                    prec_value = float(self.data_forecast ['precipitation'][i]['value'])
                    add_prec6h = add_prec6h + prec_value

                for i in range(2,-1,-1):
                    prec_value = float(self.data_forecast ['precipitation'][i]['value'])
                    add_prec3h = add_prec3h  + prec_value

                if add_prec3h >= 100:
                    type_rainstome = {'3小时降雨量':add_prec3h,'暴雨预警':'红色3小时暴雨预警,加固或者拆除易被风吹动的搭建物, 人员应当待在防风安全的地方，当台风中心经过时风力会减小或者静止一段时间，切记强风将会突然吹袭，应当继续留在安全处避风，危房人员及时转移；相关地区应当注意防范强降水可能引发的山洪、地质灾害。'}
                elif add_prec3h >= 50.0:
                    type_rainstome = {'3小时降雨量':add_prec3h,'暴雨预警':'橙色3小时暴雨预警,停止集会、停课、停业（除特殊行业外）,做好山洪、滑坡、泥石流等灾害的防御和抢险工作。'}
                elif add_prec6h >= 50.0:
                    type_rainstome = {'6小时降雨量':add_prec6h,'暴雨预警':'黄色6小时暴雨预警交通管理部门应当根据路况在强降雨路段采取交通管制措施，在积水路段实行交通引导；切断低洼地带有危险的室外电源，暂停在空旷地方的户外作业，转移危险地带人员和危房居民到安全场所避雨'}
                elif add_prec12h >= 50.0:
                    type_rainstome = {'12小时降雨量':add_prec12h,'暴雨预警':'蓝色12小时暴雨预警学校、幼儿园采取适当措施，保证学生和幼儿安全,驾驶人员应当注意道路积水和交通阻塞，确保安全'}
                else:
                    type_rainstome = {'3小时降雨量':add_prec3h,'暴雨预警':'无预警'}
                self.attributes = type_rainstome
                self._state = round(add_prec12h,2)
            if self._sensor ==  'typhoon':
                def get_typhoon_day(self,num):
                    today_max_wind_speed = float(self.data_forecast['result']['daily']['wind'][num]['max']['speed'])
                    today_avg_wind_speed = float(self.data_forecast['result']['daily']['wind'][num]['avg']['speed'])
                    if (today_avg_wind_speed > 38 and today_avg_wind_speed < 61) or (today_max_wind_speed > 61 and today_max_wind_speed < 89):
                        type_typhoon = {num_day_type[num]+'最大风速':today_max_wind_speed,num_day_type[num]+'台风预警':'蓝色'}
                    elif (today_avg_wind_speed > 61 and today_avg_wind_speed < 89) or (today_max_wind_speed > 88 and today_max_wind_speed < 118):
                        type_typhoon = {num_day_type[num]+'最大风速':today_max_wind_speed,num_day_type[num]+'台风预警':'黄色'}
                    elif today_max_wind_speed > 117.72 and today_max_wind_speed < 132.84:
                        type_typhoon = {num_day_type[num]+'最大风速':today_max_wind_speed,num_day_type[num]+'台风预警':'12级台风，陆上极少，造成巨大灾害，房屋吹走'}
                    elif today_max_wind_speed >= 132.84 and today_max_wind_speed < 149.44:
                        type_typhoon = {num_day_type[num]+'最大风速':today_max_wind_speed,num_day_type[num]+'台风预警':'13级台风，中等台风'}
                    elif today_max_wind_speed >= 149.44 and today_max_wind_speed < 166.44:
                        type_typhoon = {num_day_type[num]+'最大风速':today_max_wind_speed,num_day_type[num]+'台风预警':'14级台风，强台风'}
                    elif today_max_wind_speed >= 166.44 and today_max_wind_speed < 183.77:
                        type_typhoon = {num_day_type[num]+'最大风速':today_max_wind_speed,num_day_type[num]+'台风预警':'15级台风，极强台风'}
                    elif today_max_wind_speed >= 183.77 and today_max_wind_speed < 201.0:
                        type_typhoon = {num_day_type[num]+'最大风速':today_max_wind_speed,num_day_type[num]+'台风预警':'16级台风，至强台风'}
                    elif today_max_wind_speed >= 201.0 and today_max_wind_speed < 220.0:
                        type_typhoon = {num_day_type[num]+'最大风速':today_max_wind_speed,num_day_type[num]+'台风预警':'17级台风，台风之王'}
                    elif today_max_wind_speed >= 220.0:
                        type_typhoon = {num_day_type[num]+'最大风速':today_max_wind_speed,num_day_type[num]+'台风预警':'17级台风，极强台风之王'}
                    elif today_max_wind_speed >= 250.0:
                        type_typhoon = {num_day_type[num]+'最大风速':today_max_wind_speed,num_day_type[num]+'台风预警':'18级台风，什么也别想了，避难要紧'}
                    else:
                        type_typhoon = {num_day_type[num]+'最大风速':today_max_wind_speed,num_day_type[num]+'台风预警':'无预警'}
                    return  type_typhoon
                add_typhoon_data = {}
                for i in range(4,-1,-1):
                    typhoon_data = get_typhoon_day(self,i)
                    add_typhoon_data = dict(typhoon_data, **add_typhoon_data)
                self.attributes = add_typhoon_data
                self._state =  float(self.data_forecast['result']['daily']['wind'][0]['max']['speed'])

            if self._sensor == 'high_temp':
                def get_high_temp_day(self,num):
                    day_max_temp = float(self.data_forecast['result']['daily']['temperature'][num]['max'])
                    if day_max_temp > 34.0 and day_max_temp < 37.0:
                        type_hige_temp = {num_day_type[num]+'最高温度':day_max_temp, num_day_type[num]+'高温预警':'将会出现34°C以上高温，其中最高温度将达到{high_temp}°C，天气热，请注意防暑降温；户外工作或活动时，要避免长时间在阳光下曝晒，同时采取防晒措施。'.format(high_temp=day_max_temp)}
                    elif day_max_temp > 36.0 and day_max_temp < 40.0:
                        type_hige_temp = {num_day_type[num]+'最高温度':day_max_temp,num_day_type[num]+'高温预警':'将会出现36°C以上高温，其中最高温度将达到{high_temp}°C，天气炎热，容易中暑，请注意(尤其是老弱病人)防暑降温；应尽量避免在强烈阳光下进行户外工作或活动。'.format(high_temp=day_max_temp)}
                    elif day_max_temp > 39.0:
                        type_hige_temp = {num_day_type[num]+'最高温度':day_max_temp,num_day_type[num]+'高温预警':'将会出现39°C以上高温，其中最高温度将达到{high_temp}°C，天气酷热，极易中暑，请注意(尤其是老弱病人和儿童)因中暑引发其他疾病的防护措施。'.format(high_temp=day_max_temp)}
                    else:
                        type_hige_temp = {num_day_type[num]+'最高温度':day_max_temp,num_day_type[num]+'高温预警':'无预警'}
                    return type_hige_temp
                add_high_temp_data ={}
                for i in range(4, -1 ,-1):
                    high_temp_data = get_high_temp_day(self,i)
                    add_high_temp_data = dict(high_temp_data, **add_high_temp_data)
                self.attributes = add_high_temp_data
                self._state =  float(self.data_forecast['result']['daily']['temperature'][0]['max'])

            if self._sensor == 'low_temp':
                def get_low_temp_day(self,num):
                    today_avg_wind_speed = float(self.data_forecast['result']['daily']['wind'][num]['avg']['speed'])
                    if num < 4:
                        day_min_temp = float(self.data_forecast['result']['daily']['temperature'][num]['min'])
                        day2_range_temp = float(self.data_forecast['result']['daily']['temperature'][num+1]['min']) - float(self.data_forecast['result']['daily']['temperature'][num]['min'])
                    elif num == 4:
                        day_min_temp = float(self.data_forecast['result']['daily']['temperature'][num]['min'])
                        day2_range_temp = 0
                    if day_min_temp <= 4.0 and day2_range_temp > 7 and today_avg_wind_speed > 28:
                        type_low_temp = {num_day_type[num]+'最低温度':day_min_temp,num_day_type[num]+'寒潮预警':'寒潮蓝色预警将会出现4°C以下低温，其中最低温度将达到{low_temp}°C，强冷空气带来的大风降温天气，将对社会生产、居民生活产生较大影响。'.format(high_temp=day_max_temp)}
                    elif day_min_temp <= 4.0 and day2_range_temp > 9 and today_avg_wind_speed > 38:
                        type_low_temp = {num_day_type[num]+'最低温度':day_min_temp,num_day_type[num]+'寒潮预警':'寒潮黄色预警将会出现-10°C以下低温，其中最高温度将达到{low_temp}°C，人员要注意添衣防寒。有关部门和单位注意做好防冻工作。'.format(high_temp=day_max_temp)}
                    elif day_min_temp <= 0 and day2_range_temp > 11 and today_avg_wind_speed > 38:
                        type_low_temp = {num_day_type[num]+'最低温度':day_min_temp,num_day_type[num]+'寒潮预警':'寒潮橙色预警将会出现-10°C以下低温，其中最高温度将达到{low_temp}°C，人员要注意添衣防寒。有关部门和单位注意做好防冻工作。'.format(high_temp=day_max_temp)}
                    elif day_min_temp <= 0 and day2_range_temp > 15 and today_avg_wind_speed > 38:
                        type_low_temp = {num_day_type[num]+'最低温度':day_min_temp,num_day_type[num]+'寒潮预警':'寒潮红色预警将会出现-15°C以下低温，其中最高温度将达到{low_temp}°C，做好人员(尤其是老、弱、病人群)的防寒保暖工作。做好牲畜、家禽的防寒保暖工作。农业、水产业、畜牧业等要积极采取防冻措施,尽量减少损失。'.format(high_temp=day_max_temp)}
                    else:
                        type_low_temp = {num_day_type[num]+'最低温度':day_min_temp,num_day_type[num]+'寒潮预警':'无预警'}
                    return type_low_temp

                add_low_temp_data ={}
                for i in range(4, -1 ,-1):
                    low_temp_data = get_low_temp_day(self,i)
                    add_low_temp_data = dict(low_temp_data, **add_low_temp_data)
                self.attributes = add_low_temp_data
                self._state =  float(self.data_forecast['result']['daily']['temperature'][0]['min'])

            if self._sensor == 'aqi':
                def get_high_aqi_day(self,num):
                    day_max_aqi = float(self.data_forecast['result']['daily']['aqi'][num]['max'])
                    if day_max_aqi > 0.0 and day_max_aqi <= 50.0:
                        type_high_aqi = {num_day_type[num]+'最高aqi':day_max_aqi, num_day_type[num]+'空气质量':'空气质量指数为{high_aqi}，空气质量级别为一级，空气质量状况属于优。此时，空气质量令人满意，基本无空气污染，各类人群可正常活动'.format(high_aqi=day_max_aqi)}
                    elif day_max_aqi > 50.0 and day_max_aqi <= 100.0:
                        type_high_aqi = {num_day_type[num]+'最高aqi':day_max_aqi,num_day_type[num]+'空气质量':'空气质量指数为{high_aqi}，空气质量级别为二级，空气质量状况属于良。此时空气质量可接受，但某些污染物可能对极少数异常敏感人群健康有较弱影响，建议极少数异常敏感人群应减少户外活动。'.format(high_aqi=day_max_aqi)}
                    elif day_max_aqi > 100.0 and day_max_aqi <= 150.0:
                        type_high_aqi = {num_day_type[num]+'最高aqi':day_max_aqi,num_day_type[num]+'空气质量预警':'空气质量指数为{high_aqi}，空气质量级别为三级，空气质量状况属于轻度污染。此时，易感人群症状有轻度加剧，健康人群出现刺激症状。建议儿童、老年人及心脏病、呼吸系统疾病患者应减少长时间、高强度的户外锻炼'.format(high_aqi=day_max_aqi)}
                    elif day_max_aqi > 150.0 and day_max_aqi <= 200.0:
                        type_high_aqi = {num_day_type[num]+'最高aqi':day_max_aqi,num_day_type[num]+'空气质量预警':'空气质量指数为{high_aqi}，空气质量级别为四级，空气质量状况属于中度污染。此时，进一步加剧易感人群症状，可能对健康人群心脏、呼吸系统有影响，建议疾病患者避免长时间、高强度的户外锻练，一般人群适量减少户外运动。'.format(high_aqi=day_max_aqi)}
                    elif day_max_aqi > 200.0 and day_max_aqi <= 300.0:
                        type_high_aqi = {num_day_type[num]+'最高aqi':day_max_aqi,num_day_type[num]+'空气质量预警':'空气质量指数为{high_aqi}，空气质量级别为五级，空气质量状况属于重度污染。此时，心脏病和肺病患者症状显著加剧，运动耐受力降低，健康人群普遍出现症状，建议儿童、老年人和心脏病、肺病患者应停留在室内，停止户外运动，一般人群减少户外运动。'.format(high_aqi=day_max_aqi)}
                    elif day_max_aqi > 300.0:
                        type_high_aqi = {num_day_type[num]+'最高aqi':day_max_aqi,num_day_type[num]+'空气质量预警':'空气质量指数为{high_aqi}，空气质量级别为六级，空气质量状况属于严重污染。此时，健康人群运动耐受力降低，有明显强烈症状，提前出现某些疾病，建议儿童、老年人和病人应当留在室内，避免体力消耗，一般人群应避免户外活动。'.format(high_aqi=day_max_aqi)}
                    else:
                        type_high_aqi = {num_day_type[num]+'最高aqi':day_max_aqi,num_day_type[num]+'空气质量':'无预警'}
                    return type_high_aqi
                add_high_aqi_data ={}
                for i in range(4, -1 ,-1):
                    high_aqi_data = get_high_aqi_day(self,i)
                    add_high_aqi_data = dict(high_aqi_data, **add_high_aqi_data)
                self.attributes = add_high_aqi_data
                self._state =  float(self.data_forecast['result']['daily']['aqi'][0]['max'])

            if self._sensor == 'pm25':
                def get_high_pm25_day(self,num):
                    day_max_pm25 = float(self.data_forecast['result']['daily']['pm25'][num]['max'])
                    if day_max_pm25 > 0.0 and day_max_pm25 <= 35.0:
                        type_high_pm25 = {num_day_type[num]+'pm25最高':day_max_pm25, num_day_type[num]+'pm25':'pm25指数{high_pm25}，空气质量级别为一级，空气质量状况属于优。此时，空气质量令人满意，基本无空气污染，各类人群可正常活动'.format(high_pm25=day_max_pm25)}
                    elif day_max_pm25 > 35.0 and day_max_pm25 <= 75.0:
                        type_high_pm25 = {num_day_type[num]+'pm25最高':day_max_pm25, num_day_type[num]+'pm25':'pm25指数{high_pm25}，空气质量级别为二级，空气质量状况属于良。此时空气质量可接受，但某些污染物可能对极少数异常敏感人群健康有较弱影响，建议极少数异常敏感人群应减少户外活动。'.format(high_pm25=day_max_pm25)}
                    elif day_max_pm25 > 75.0 and day_max_pm25 <= 115.0:
                        type_high_pm25 = {num_day_type[num]+'pm25最高':day_max_pm25, num_day_type[num]+'pm25预警':'pm25指数{high_pm25}，空气质量级别为三级，空气质量状况属于轻度污染。此时，易感人群症状有轻度加剧，健康人群出现刺激症状。建议儿童、老年人及心脏病、呼吸系统疾病患者应减少长时间、高强度的户外锻炼'.format(high_pm25=day_max_pm25)}
                    elif day_max_pm25 > 115.0 and day_max_pm25 <= 150.0:
                        type_high_pm25 = {num_day_type[num]+'pm25最高':day_max_pm25, num_day_type[num]+'pm25预警':'pm25指数{high_pm25}，空气质量级别为四级，空气质量状况属于中度污染。此时，进一步加剧易感人群症状，可能对健康人群心脏、呼吸系统有影响，建议疾病患者避免长时间、高强度的户外锻练，一般人群适量减少户外运动。'.format(high_pm25=day_max_pm25)}
                    elif day_max_pm25 > 150.0 and day_max_pm25 <= 250.0:
                        type_high_pm25 = {num_day_type[num]+'pm25最高':day_max_pm25, num_day_type[num]+'pm25预警':'pm25指数{high_pm25}，空气质量级别为五级，空气质量状况属于重度污染。此时，心脏病和肺病患者症状显著加剧，运动耐受力降低，健康人群普遍出现症状，建议儿童、老年人和心脏病、肺病患者应停留在室内，停止户外运动，一般人群减少户外运动。'.format(high_pm25=day_max_pm25)}
                    elif day_max_pm25 > 250.0:
                        type_high_pm25 = {num_day_type[num]+'pm25最高':day_max_pm25, num_day_type[num]+'pm25预警':'pm25指数{high_pm25}，空气质量级别为六级，空气质量状况属于严重污染。此时，健康人群运动耐受力降低，有明显强烈症状，提前出现某些疾病，建议儿童、老年人和病人应当留在室内，避免体力消耗，一般人群应避免户外活动。'.format(high_pm25=day_max_pm25)}
                    else:
                        type_high_pm25 = {num_day_type[num]+'pm25最高':day_max_pm25, num_day_type[num]+'pm25预警':'无预警'}
                    return type_high_pm25
                add_high_pm25_data ={}
                for i in range(4, -1 ,-1):
                    high_pm25_data = get_high_pm25_day(self,i)
                    add_high_pm25_data = dict(high_pm25_data, **add_high_pm25_data)
                self.attributes = add_high_pm25_data
                self._state =  float(self.data_forecast['result']['daily']['pm25'][0]['max'])

            if self._sensor == 'precipitation':
                def get_high_precipitation_day(self,num):
                    day_max_precipitation = float(self.data_forecast['result']['daily']['precipitation'][num]['max'])
                    if day_max_precipitation > 0.0 and day_max_precipitation <= 2.5:
                        type_high_precipitation = {num_day_type[num]+'最大小时降雨量':day_max_precipitation, num_day_type[num]+'降雨':'最大降雨量{high_precipitation}，小雨'.format(high_precipitation=day_max_precipitation)}
                    elif day_max_precipitation > 2.5 and day_max_precipitation <= 8.0:
                        type_high_precipitation = {num_day_type[num]+'最大小时降雨量':day_max_precipitation, num_day_type[num]+'降雨':'最大降雨量{high_precipitation}，中雨'.format(high_precipitation=day_max_precipitation)}
                    elif day_max_precipitation > 8.0 and day_max_precipitation <= 15.9:
                        type_high_precipitation = {num_day_type[num]+'最大小时降雨量':day_max_precipitation, num_day_type[num]+'降雨预警':'最大降雨量{high_precipitation}，大雨'.format(high_precipitation=day_max_precipitation)}
                    elif day_max_precipitation > 15.9:
                        type_high_precipitation = {num_day_type[num]+'最大小时降雨量':day_max_precipitation, num_day_type[num]+'降雨预警':'最大降雨量{high_precipitation}，暴雨'.format(high_precipitation=day_max_precipitation)}
                    else:
                        type_high_precipitation = {num_day_type[num]+'最大小时降雨量':day_max_precipitation, num_day_type[num]+'降雨':'无预警'}
                    return type_high_precipitation
                add_high_precipitation_data ={}
                for i in range(4, -1 ,-1):
                    high_precipitation_data = get_high_precipitation_day(self,i)
                    add_high_precipitation_data = dict(high_precipitation_data, **add_high_precipitation_data)
                self.attributes = add_high_precipitation_data
                self._state =  float(self.data_forecast['result']['daily']['precipitation'][0]['max'])


class CaiyunWeatherUI(WeatherEntity):
    """Representation of a weather condition."""

    def __init__(self,hass, forecastjson_path, tracker_id):
        """Initialize the Demo weather."""

        self._hass = hass
        self._forecastjson_path = forecastjson_path
        self._condition = 'Sunshine'
        self._temperature = 21
        self._temperature_unit = TEMP_CELSIUS
        self._humidity = 92
        self._pressure = 1000
        self._wind_speed = 0.5
        self._forecast = []
        self.forecastjson_data = {}

        self.forecast_data = {}
        self.tracker_id = tracker_id
        self.update()

        if self.tracker_id != 'disable':
            self.entity_id = generate_entity_id(
                'weather.{}', 'CaiyunWeatherUI_'+self.tracker_id.replace('.','_'), hass=self._hass)
            self.friendly_name = self._hass.states.get(self.tracker_id).attributes.get('friendly_name')+'所在地天气概况'
        else:
            if self._hass.states.get('zone.home').attributes.get('friendly_name') == 'Home':
                self.friendly_name = '彩云天气'
                self.entity_id = generate_entity_id(
                    'weather.{}', 'CaiyunWeatherUI_Home', hass=self._hass)
            else:
                self.friendly_name = self._hass.states.get('zone.home').attributes.get('friendly_name')+'所在地天气概况'
                self.entity_id = generate_entity_id(
                    'weather.{}', 'CaiyunWeatherUI_HOME', hass=self._hass)


    @property
    def name(self):
        """Return the name of the sensor."""
        return self.friendly_name

    @property
    def should_poll(self):
        """No polling needed for a demo weather condition."""
        return False

    @property
    def temperature(self):
        """Return the temperature."""
        return self._temperature

    @property
    def temperature_unit(self):
        """Return the unit of measurement."""
        return self._temperature_unit

    @property
    def humidity(self):
        """Return the humidity."""
        return self._humidity

    @property
    def wind_speed(self):
        """Return the wind speed."""
        return self._wind_speed

    @property
    def pressure(self):
        """Return the pressure."""
        return self._pressure

    @property
    def condition(self):
        """Return the weather condition."""
        if self._condition in CONDITION_CLASSES.keys():
            return CONDITION_CLASSES[self._condition]
        else:
            return '天气状况不存在'

    @property
    def attribution(self):
        """Return the attribution."""
        return 'Powered by Home Assistant'

    @property
    def forecast(self):
        """Return the forecast."""
        return self.forecast_data

    def update(self):
        """Get the latest data from Yahoo! and updates the states."""
        try:
            with open(self._forecastjson_path, 'r', encoding='utf-8') as file_data:
                self.forecastjson_data = json.load(file_data)

        except (IndexError, FileNotFoundError, IsADirectoryError,
                UnboundLocalError):
            _Log.warning("File or data not present at the moment: %s",
                            os.path.basename(self.forecastjson_data))
            return
        forecast_data = []
        for i in range(0, 27 ,4):
            data_dict = {
                ATTR_FORECAST_TIME: self.forecastjson_data['result']['hourly']['temperature'][i]['datetime'],
                ATTR_FORECAST_TEMP: self.forecastjson_data['result']['hourly']['temperature'][i]['value'],
            }
            #reftime = reftime + timedelta(hours=4)
            forecast_data.append(data_dict)
        self.forecast_data = forecast_data
        self._temperature = self.forecastjson_data['result']['daily']['temperature'][0]['avg']
        self._humidity = round(float(self.forecastjson_data['result']['daily']['humidity'][0]['avg'])*100)
        self._wind_speed = self.forecastjson_data['result']['daily']['wind'][0]['avg']['speed']
        if 'pres' in self.forecastjson_data['result']['daily']:
            self._pressure = self.forecastjson_data['result']['daily']['pres'][0]['avg']
        else:
            self._pressure = '无气压数据'
        self._condition = self.forecastjson_data['result']['daily']['skycon'][0]['value']

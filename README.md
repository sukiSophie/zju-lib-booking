## 已经实现的API
1. seat(获取当前区域所有座位的情况)
    - request_url:https://booking.lib.zju.edu.cn/api/Seat/seat
    - payload:
            {
                "area":"58",
                "segment":"1386529",
                "day":"<YYYY-MM-DD>",
                "startTime":"00:01",
                "endTime":"23:59",
                "authorization":"{self._jwt_token}"
            }
    - response:
            {
                "code": 1,
                "msg": "操作成功",
                "data": [
                    {
                        "id": "6046",
                        "no": "Z2F001",
                        "name": "Z2F001",
                        "area": "58",
                        "category": "25",
                        "point_x": "67.604159999999993",
                        "point_x2": null,
                        "point_x3": null,
                        "point_x4": null,
                        "point_y": "23.158909999999999",
                        "point_y2": null,
                        "point_y3": null,
                        "point_y4": null,
                        "width": "2.65625",
                        "height": "5.6201549999999996",
                        "status": "6",
                        "status_name": "使用中",
                        "area_name": "二层南",
                        "area_levels": "3",
                        "area_type": "1",
                        "area_color": null,
                        "in_label": 1
                    },
                    ..., //此处省略部分内容
                    {
                        "id": "6077",
                        "no": "Z2F032",
                        "name": "Z2F032",
                        "area": "58",
                        "category": "25",
                        "point_x": "28.48958",
                        "point_x2": null,
                        "point_x3": null,
                        "point_x4": null,
                        "point_y": "58.333329999999997",
                        "point_y2": null,
                        "point_y3": null,
                        "point_y4": null,
                        "width": "2.9166669999999999",
                        "height": "5.8139529999999997",
                        "status": "6",
                        "status_name": "使用中",
                        "area_name": "二层南",
                        "area_levels": "3",
                        "area_type": "1",
                        "area_color": null,
                        "in_label": 1
                    }
                ]
            }

2. confirm(预约座位操作)
    - request_url:https://booking.lib.zju.edu.cn/api/Seat/confirm
    - payload:
            {
                "aesjson":"<get_encrypted_seat_request函数的返回值>",
                "authorization":"{self._jwt_token}"
            }
    - response:
            {
                "code": 1,
                "msg": "预约成功",
                "time": "10:23-23:59",
                "seat": "主馆-二层-二层北 Z2F204",
                "new_time": "2025-11-06 10:23-23:59",
                "area": "主馆-二层-二层北",
                "no": "Z2F204"
            }
            或者
            {
                "code":0,
                "msg":"当前时段存在预约，不可重复预约!",
                "seat":null
            }

3. list(列出所有区域的大概情况)
    - request_url:https://booking.lib.zju.edu.cn/reserve/index/list
    - payload:
            {
                "id":"1",
                "date":"<YYYY-MM-DD>",
                "categoryIds":["1"],
                "members":0,
                "size":10,
                "page":1,
                "authorization":"{self._jwt_token}"
                }
    - response:
            {
                "code": 0,
                "data": {
                    "page": 1,
                    "size": 10,
                    "list": [
                        {
                            "id": "58",
                            "name": "二层南",
                            "enname": "",
                            "nameMerge": "主馆-二层-二层南",
                            "ennameMerge": "-2 Floor-",
                            "sub_title": "",
                            "contents": "",
                            "en_sub_title": "",
                            "en_contents": "",
                            "type_id": "1",
                            "type_name": "普通座位",
                            "type_enname": "Ordinary Seat",
                            "firstimg": "https:\/\/booking.lib.zju.edu.cn\/home\/images\/first\/area\/58\/2FS.jpg",
                            "img": [
                                "https:\/\/booking.lib.zju.edu.cn\/home\/images\/carousel\/area\/58\/2FS.jpg"
                            ],
                            "ROW_NUMBER": "21",
                            "storeyName": "二层",
                            "enStoreyName": "2 Floor",
                            "premisesName": "主馆",
                            "enPremisesName": "",
                            "boutique": [],
                            "total_num": 32,
                            "free_num": 1
                        },
                        ...,  //省略部分内容
                        {
                            "id": "67",
                            "name": "五层东",
                            "enname": "",
                            "nameMerge": "主馆-五层-五层东",
                            "ennameMerge": "-5 Floor-",
                            "sub_title": "",
                            "contents": "",
                            "en_sub_title": "",
                            "en_contents": "",
                            "type_id": "1",
                            "type_name": "普通座位",
                            "type_enname": "Ordinary Seat",
                            "firstimg": "https:\/\/booking.lib.zju.edu.cn\/home\/images\/first\/area\/67\/5FE.jpg",
                            "img": [
                                "https:\/\/booking.lib.zju.edu.cn\/home\/images\/carousel\/area\/67\/5FE.jpg"
                            ],
                            "ROW_NUMBER": "30",
                            "storeyName": "五层",
                            "enStoreyName": "5 Floor",
                            "premisesName": "主馆",
                            "enPremisesName": "",
                            "boutique": [],
                            "total_num": 64,
                            "free_num": 11
                        }
                    ],
                    "totalPage": 2,
                    "count": 20
                },
                "msg": "成功"
            }

## 关于segment
每个区域的segment是固定的,具体如下:
    {
        "二层南":1386529,
        "二层北":1387307,
        "三层东":1388085,
        "三层南":1388863,
        "三层北":1389641,
        "四层东":1390419,
        "四层南":1391197,
        "四层西":1391975,
        "四层北":1392753,
        "五层东":1393531
    }

## 关于预约策略
1. 若多个区域有空座位,则优先级:二层北>二层南>三层>四层>五层
2. 监控空余座位策略:间隔很短的刷新时间(允许用户调整,默认1s)调用list这个API,检测各个区域的"free_num"值

## 交互界面
本程序面向运行在Github Workflow中,接受用户如下参数:学号,密码,刷新时间(非必需,默认1s).程序会打印日志.
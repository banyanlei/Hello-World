<?php

namespace App\Http\Controllers\Collection;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * Created by PhpStorm.
 * User: caoyang
 * Date: 2017/4/14
 * Time: 15:23
 */
class CollectionController extends Controller
{

  public function __construct()
  {
    $this->showWarnNumbers = 15;
  }

  //登录
  public function Login(Request $request)
  {
    $username = htmlspecialchars($request->input('userName'));
    $password = htmlspecialchars($request->input('password'));

    if (empty($username) || empty($password)) {
      return response()->json(['status' => 1, 'msg' => '用户名和密码未填写完整']);
    }

    $userInfo = DB::table('auth_user')->select('id')->where('username', '=', $username)->get();
    if (empty($userInfo)) {
      return response()->json(['status' => 1, 'msg' => '该用户不存在']);
    } else {
      $password = base64_encode(md5(htmlspecialchars($password)));
      $userInfo = DB::table('auth_user')
        ->where('username', '=', $username)
        ->where('password', '=', $password)
        ->get();
      if (empty($userInfo)) {
        return response()->json(['status' => 1, 'msg' => '用户密码有误']);
      } else {
        DB::table('auth_user')->where('id', '=', $userInfo[0]->id)->update(['login_time' => date('Y-m-d H:i:s', time())]);
        return response()->json(['status' => 0, 'msg' => '登录成功'])->withCookie('username', $username);
      }
    }
  }

  //日志收集趋势
  public function LogTrend()
  {
    $trendList = [];
    $trendResult = DB::select('select DATE_FORMAT(attack_timestamp,\'%Y%m%d\') day,count(id) warncount,
                          SUM(case when log_id = \'1\' then 1 else 0 end) logcount  from attack_device group by day;');
    if (empty($trendResult)) {
      return response()->json(['status' => 1, 'msg' => '暂无数据']);
    }
    foreach ($trendResult as $result) {
      $trendStatistic = ['warn' => $result->warncount, 'log' => $result->logcount];
      $trendList[$result->day] = $trendStatistic;
    }
    return response()->json(['status' => 0, 'trendList' => $trendList]);
  }

  //实时预警
  public function RealtimeWarn()
  {
    $warnList = [];
    $warnResult = DB::table('attack_device')
      ->select('device_id', 'attack_timestamp', 'attack_ip')
      ->orderby('id', 'desc')
      ->take($this->showWarnNumbers)
      ->get();
    if (empty($warnResult)) {
      return response()->json(['status' => 1, 'msg' => '暂无数据']);
    }
    foreach ($warnResult as $result) {
      $warnList[] = ['deviceNum' => $result->device_id, 'time' => $result->attack_timestamp, 'attackIp' => $result->attack_ip];
    }
    return response()->json(['status' => 0, 'warnList' => $warnList]);
  }

  //设备分布图展示
  public function DeviceLocate()
  {
    $deviceLocateInfo = [];
    $deviceNum = DB::table('device_info')->count('device_id');
    $deviceWarnNum = DB::table('attack_device')->distinct()->count('device_id');

    $deviceLocateResult = DB::table('device_info')
      ->select(DB::raw('count(device_location) as count'), 'device_location')
      ->groupby('device_location')
      ->get();
    if (empty($deviceLocateResult)) {
      return response()->json(['status' => 1, 'deviceNum' => $deviceNum, 'deviceWarnNum' => $deviceWarnNum, 'msg' => '暂无设备位置信息']);
    }
    foreach ($deviceLocateResult as $result) {
      $deviceLocateList[] = ['name' => $result->device_location, 'value' => $result->count];
    }
    $deviceLocateInfo['deviceNum'] = $deviceNum;
    $deviceLocateInfo['deviceWarnNum'] = $deviceWarnNum;
    $deviceLocateInfo['deviceLocateList'] = $deviceLocateList;
    return response()->json(['status' => 0, 'deviceLocateInfo' => $deviceLocateInfo]);
  }

  //攻击源分布图
  public function ResourceLocate()
  {
    $attackNum = DB::table('attack_device')->count('id');//攻击次数
    $reourceLocateInfo = [];
    $reourceLocateResult = DB::table('attack_device')
      ->join('device_info','attack_device.device_id','=','device_info.device_id')
      ->select(DB::raw('count(*) as count'), 'attack_device.attack_location', 'device_info.device_location')
      ->groupby('attack_device.attack_location','device_info.device_location')
      ->get();
    if (empty($reourceLocateResult)) {
      return response()->json(['status' => 1, 'msg' => '暂无攻击源地址信息', 'attackNum' => $attackNum]);
    }
    foreach ($reourceLocateResult as $result) {
      $resourceLocate = ['name' => $result->attack_location];
      $deviceLocateUnion = ['name' => $result->device_location, 'value' => $result->count];
      $reourceLocateList[] = ['resourceLocate' => $resourceLocate, 'deviceLocateUnion' => $deviceLocateUnion];
    }
    $reourceLocateInfo['attackNum'] = $attackNum;
    $reourceLocateInfo['reourceLocateList'] = $reourceLocateList;
    return response()->json(['status' => 0, 'reourceLocateInfo' => $reourceLocateInfo]);
  }

  //返回被攻击设备
  public function Attackeddevice()
  {
    $attackeddevices = DB::table('attack_device')->distinct()->pluck('device_id');
    return response()->json(['status' => 0, 'attackeddevices' => $attackeddevices]);
  }

  //根据被选设备展示攻击源分布图
  public function ResourceLocateByDevice(Request $request)
  {
    $device = htmlspecialchars($request->input('device'));
    $attackeddevices = DB::table('attack_device')->distinct()->pluck('device_id');
    if (!in_array($device, $attackeddevices)) {
      return response()->json(['status' => 1, 'msg' => '无效设备，请重行选择']);
    }
    $attackNum = DB::table('attack_device')->where('device_id',$device)->count('id');//攻击次数
    $reourceLocateInfo = [];
    $reourceLocateResult = DB::table('attack_device')
      ->join('device_info','attack_device.device_id','=','device_info.device_id')
      ->select(DB::raw('count(*) as count'), 'attack_device.attack_location', 'device_info.device_location')
      ->where('attack_device.device_id',$device)
      ->groupby('attack_device.attack_location','device_info.device_location')
      ->get();
    if (empty($reourceLocateResult)) {
      return response()->json(['status' => 1, 'msg' => '暂无攻击源地址信息', 'attackNum' => $attackNum]);
    }
    foreach ($reourceLocateResult as $result) {
      $resourceLocate = ['name' => $result->attack_location];
      $deviceLocateUnion = ['name' => $result->device_location, 'value' => $result->count];
      $reourceLocateList[] = ['resourceLocate' => $resourceLocate, 'deviceLocateUnion' => $deviceLocateUnion];
    }
    $reourceLocateInfo['attackNum'] = $attackNum;
    $reourceLocateInfo['reourceLocateList'] = $reourceLocateList;
    dd($reourceLocateInfo);
    return response()->json(['status' => 0, 'reourceLocateInfo' => $reourceLocateInfo]);
  }
}
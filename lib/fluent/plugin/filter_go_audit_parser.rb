#
# Copyright 2021- haccht
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "fluent/plugin/filter"

module Fluent
  module Plugin
    class GoAuditParserFilter < Fluent::Plugin::Filter
      Fluent::Plugin.register_filter("go_audit_parser", self)

      # https://github.com/torvalds/linux/blob/master/include/uapi/linux/audit.h
      # https://github.com/linux-audit/audit-userspace/blob/master/lib/libaudit.h
      TYPES = {
        1100 => 'user_auth',
        1101 => 'user_acct',
        1102 => 'user_mgmt',
        1103 => 'cred_acq',
        1104 => 'cred_disp',
        1105 => 'user_start',
        1106 => 'user_end',
        1107 => 'user_avc',
        1108 => 'user_chauthtok',
        1109 => 'user_err',
        1110 => 'cred_refr',
        1111 => 'usys_config',
        1112 => 'user_login',
        1113 => 'user_logout',
        1114 => 'add_user',
        1115 => 'del_user',
        1116 => 'add_group',
        1117 => 'del_group',
        1118 => 'dac_check',
        1119 => 'chgrp_id',
        1120 => 'test',
        1121 => 'trusted_app',
        1122 => 'user_selinux_err',
        1123 => 'user_cmd',
        1124 => 'user_tty',
        1125 => 'chuser_id',
        1126 => 'grp_auth',
        1127 => 'system_boot',
        1128 => 'system_shutdown',
        1129 => 'system_runlevel',
        1130 => 'service_start',
        1131 => 'service_stop',
        1132 => 'grp_mgmt',
        1133 => 'grp_chauthtok',
        1134 => 'mac_check',
        1135 => 'acct_lock',
        1136 => 'acct_unlock',
        1137 => 'user_device',
        1138 => 'software_update',
        1200 => 'daemon_start',
        1201 => 'daemon_end',
        1202 => 'daemon_abort',
        1203 => 'daemon_config',
        1204 => 'daemon_reconfig',
        1205 => 'daemon_rotate',
        1206 => 'daemon_resume',
        1207 => 'daemon_accept',
        1208 => 'daemon_close',
        1209 => 'daemon_err',
        1300 => 'syscall',
        1302 => 'path',
        1303 => 'ipc',
        1304 => 'socketcall',
        1305 => 'config_change',
        1306 => 'sockaddr',
        1307 => 'cwd',
        1309 => 'execve',
        1311 => 'ipc_set_perm',
        1312 => 'mq_open',
        1313 => 'mq_sendrecv',
        1314 => 'mq_notify',
        1315 => 'mq_getsetattr',
        1316 => 'kernel_other',
        1317 => 'fd_pair',
        1318 => 'obj_pid',
        1319 => 'tty',
        1320 => 'eoe',
        1321 => 'bprm_fcaps',
        1322 => 'capset',
        1323 => 'mmap',
        1324 => 'netfilter_pkt',
        1325 => 'netfilter_cfg',
        1326 => 'seccomp',
        1327 => 'proctitle',
        1328 => 'feature_change',
        1329 => 'replace',
        1330 => 'kern_module',
        1331 => 'fanotify',
        1332 => 'time_injoffset',
        1333 => 'time_adjntpval',
        1334 => 'bpf',
        1335 => 'event_listener',
        1400 => 'avc',
        1401 => 'selinux_err',
        1402 => 'avc_path',
        1403 => 'mac_policy_load',
        1404 => 'mac_status',
        1405 => 'mac_config_change',
        1406 => 'mac_unlbl_allow',
        1407 => 'mac_cipsov4_add',
        1408 => 'mac_cipsov4_del',
        1409 => 'mac_map_add',
        1410 => 'mac_map_del',
        1411 => 'mac_ipsec_addsa',
        1412 => 'mac_ipsec_delsa',
        1413 => 'mac_ipsec_addspd',
        1414 => 'mac_ipsec_delspd',
        1415 => 'mac_ipsec_event',
        1416 => 'mac_unlbl_stcadd',
        1417 => 'mac_unlbl_stcdel',
        1418 => 'mac_calipso_add',
        1419 => 'mac_calipso_del',
        1500 => 'aa',
        1501 => 'apparmor_audit',
        1502 => 'apparmor_allowed',
        1503 => 'apparmor_denied',
        1504 => 'apparmor_hint',
        1505 => 'apparmor_status',
        1506 => 'apparmor_error',
        1507 => 'apparmor_kill',
        1700 => 'anom_promiscuous',
        1701 => 'anom_abend',
        1702 => 'anom_link',
        1703 => 'anom_creat',
        1800 => 'integrity_data',
        1801 => 'integrity_metadata',
        1802 => 'integrity_status',
        1803 => 'integrity_hash',
        1804 => 'integrity_pcr',
        1805 => 'integrity_rule',
        1806 => 'integrity_evm_xattr',
        1807 => 'integrity_policy_rule',
        1899 => 'integrity_last_msg',
        2000 => 'kernel',
        2100 => 'anom_login_failures',
        2101 => 'anom_login_time',
        2102 => 'anom_login_sessions',
        2103 => 'anom_login_acct',
        2104 => 'anom_login_location',
        2105 => 'anom_max_dac',
        2106 => 'anom_max_mac',
        2107 => 'anom_amtu_fail',
        2108 => 'anom_rbac_fail',
        2109 => 'anom_rbac_integrity_fail',
        2110 => 'anom_crypto_fail',
        2111 => 'anom_access_fs',
        2112 => 'anom_exec',
        2113 => 'anom_mk_exec',
        2114 => 'anom_add_acct',
        2115 => 'anom_del_acct',
        2116 => 'anom_mod_acct',
        2117 => 'anom_root_trans',
        2118 => 'anom_login_service',
        2119 => 'anom_login_root',
        2120 => 'anom_origin_failures',
        2121 => 'anom_session',
        2200 => 'resp_anomaly',
        2201 => 'resp_alert',
        2202 => 'resp_kill_proc',
        2203 => 'resp_term_access',
        2204 => 'resp_acct_remote',
        2205 => 'resp_acct_lock_timed',
        2206 => 'resp_acct_unlock_timed',
        2207 => 'resp_acct_lock',
        2208 => 'resp_term_lock',
        2209 => 'resp_sebool',
        2210 => 'resp_exec',
        2211 => 'resp_single',
        2212 => 'resp_halt',
        2213 => 'resp_origin_block',
        2214 => 'resp_origin_block_timed',
        2215 => 'resp_origin_unblock_timed',
        2300 => 'user_role_change',
        2301 => 'role_assign',
        2302 => 'role_remove',
        2303 => 'label_override',
        2304 => 'label_level_change',
        2305 => 'user_labeled_export',
        2306 => 'user_unlabeled_export',
        2307 => 'dev_alloc',
        2308 => 'dev_dealloc',
        2309 => 'fs_relabel',
        2310 => 'user_mac_policy_load',
        2311 => 'role_modify',
        2312 => 'user_mac_config_change',
        2313 => 'user_mac_status',
        2400 => 'crypto_test_user',
        2401 => 'crypto_param_change_user',
        2402 => 'crypto_login',
        2403 => 'crypto_logout',
        2404 => 'crypto_key_user',
        2405 => 'crypto_failure_user',
        2406 => 'crypto_replay_user',
        2407 => 'crypto_session',
        2408 => 'crypto_ike_sa',
        2409 => 'crypto_ipsec_sa',
        2500 => 'virt_control',
        2501 => 'virt_resource',
        2502 => 'virt_machine_id',
        2503 => 'virt_integrity_check',
        2504 => 'virt_create',
        2505 => 'virt_destroy',
        2506 => 'virt_migrate_in',
        2507 => 'virt_migrate_out',
      }

      def filter_with_time(tag, time, record)
        if record.key?('messages') && record.key?('uid_map')
          messages = record.delete('messages')
          uid_map  = record.delete('uid_map')

          new_messages = messages.each.with_object({}) do |message, new_messages|
            type, data = message.values_at('type', 'data')

            name = TYPES[type.to_i]
            hash = { 'type' => type.to_i }
            parseline(data).each do |key, val|
              case key
              when 'msg'
                hash[key] = parseline(val)
              when 'saddr'
                hash[key] = sockaddr(val)
              when 'proctitle'
                hash[key] = packhex(val)
              when 'uid', 'euid', 'suid', 'ouid', 'fsuid', 'auid'
                hash[key] = uid(val, uid_map)
              when 'gid', 'egid', 'sgid', 'ogid', 'fsgid'
                hash[key] = val.to_i
              when 'syscall', 'pid', 'ses', 'argc', 'inode'
                hash[key] = val.to_i
              else
                hash[key] = val
              end
            end

            new_messages.update(name => hash)
          end

          record['messages']      = new_messages
          record['message_types'] = new_messages.keys
        end

        if record.key?('timestamp')
          timestamp = record.delete('timestamp').to_f
          time = Fluent::EventTime.from_time(Time.at(timestamp))
        end

        return time, record
      end

      def parseline(text)
        regex = /([^\s=]+)=('[^']*'|"[^"]*"|\S+)/
        text.scan(regex).each.with_object({}) do |(key, val), hash|
          val = val[1..-2] if val.start_with?(/['"]/)
          hash[key] = val
        end
      end

      def uid(id, uid_map)
        { 'id' => id.to_i, 'name' => uid_map[id] }
      end

      def packhex(text)
        [text].pack("H*").gsub(/[^[:print:]]/, ' ')
      end

      def sockaddr(text)
        addr = {}

        case text[0, 2].hex + (256 * text[2, 2].hex)
        when 1
          pos = text.index('00', 4) - 4
          pos = text.size - 4 if pos < 0
          addr.update('family'    => 'local')
          addr.update('path'      => packhex(text[4, pos]))
          addr.update('unknown'   => text[pos+4..-1]) if text.size > pos + 5
        when 2
          addr.update('family'    => 'inet')
          addr.update('port'      => (text[4, 2].hex * 256) + text[6, 2].hex)
          addr.update('ip'        => text[8, 8].scan(/.{2}/).map{ |x| x.hex }.join("."))
          addr.update('unknown'   => text[16..-1]) if text.length > 16
        when 10
          addr.update('family'    => 'inet6')
          addr.update('port'      => (text[4, 2].hex * 256) + text[6, 2].hex)
          addr.update('flow_info' => text[8, 8])
          addr.update('ip'        => text[16, 32].scan(/.{4}/).map{ |x| x.downcase }.join(":"))
          addr.update('scope_id'  => text[48, 8])
          addr.update('unknown'   => text[56..-1]) if text.size > 56
        else
          addr.update('unknown' => text[4..-1])
        end

        addr
      end
    end
  end
end

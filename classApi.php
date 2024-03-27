<?php
class RouterosAPI
{
    public $debug = false;
    public $connected = false;
    public $port = 8728;
    public $ssl = false;
    public $timeout = 3;
    public $attempts = 5;
    public $delay = 3;
    public $socket;

    public function isIterable($var)
    {
        return $var !== null && (is_array($var) || $var instanceof Traversable || $var instanceof Iterator || $var instanceof IteratorAggregate);
    }

    public function debug($text)
    {
        if ($this->debug) {
            echo $text . "\n";
        }
    }

    public function encodeLength($length)
    {
        if ($length < 0x80) {
            return chr($length);
        } elseif ($length < 0x4000) {
            return chr(($length >> 8) | 0x80) . chr($length & 0xFF);
        } elseif ($length < 0x200000) {
            return chr(($length >> 16) | 0xC0) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        } elseif ($length < 0x10000000) {
            return chr(($length >> 24) | 0xE0) . chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        } else {
            return chr(0xF0) . chr(($length >> 24) & 0xFF) . chr(($length >> 16) & 0xFF) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF);
        }
    }

    public function connect($ip, $login, $password)
    {
        for ($attempt = 1; $attempt <= $this->attempts; $attempt++) {
            $this->connected = false;
            $protocol = ($this->ssl ? 'ssl://' : '');
            $context = stream_context_create(['ssl' => ['ciphers' => 'ADH:ALL', 'verify_peer' => false, 'verify_peer_name' => false]]);
            $this->debug("Connection attempt #$attempt to $protocol$ip:{$this->port}...");

            try {
                $this->socket = stream_socket_client("$protocol$ip:{$this->port}", $error_no, $error_str, $this->timeout, STREAM_CLIENT_CONNECT, $context);
                if ($this->socket) {
                    socket_set_timeout($this->socket, $this->timeout);
                    $this->write('/login', false);
                    $this->write('=name=' . $login, false);
                    $this->write('=password=' . $password);
                    $response = $this->read(false);
                    if (isset($response[0]) && $response[0] == '!done') {
                        if (!isset($response[1])) {
                            $this->connected = true;
                            break;
                        } else {
                            $matches = [];
                            if (preg_match_all('/[^=]+/i', $response[1], $matches)) {
                                if ($matches[0][0] == 'ret' && strlen($matches[0][1]) == 32) {
                                    $this->write('/login', false);
                                    $this->write('=name=' . $login, false);
                                    $this->write('=response=00' . md5(chr(0) . $password . pack('H*', $matches[0][1])));
                                    $response = $this->read(false);
                                    if (isset($response[0]) && $response[0] == '!done') {
                                        $this->connected = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    fclose($this->socket);
                }
            } catch (Exception $e) {
                $this->debug('Exception caught: ' . $e->getMessage());
            }
            sleep($this->delay);
        }

        $this->debug($this->connected ? 'Connected...' : 'Error...');
        return $this->connected;
    }

    public function disconnect()
    {
        if (is_resource($this->socket)) {
            fclose($this->socket);
        }
        $this->connected = false;
        $this->debug('Disconnected...');
    }


    public function parseResponse($response)
    {
        $PARSED = array();
        foreach ($response as $x) {
            if (in_array($x, array('!fatal', '!re', '!trap'))) {
                if ($x == '!re') {
                    $PARSED[] = array(); // Tambahkan array kosong ke $PARSED
                    $CURRENT = &$PARSED[count($PARSED) - 1]; // Mengakses array terakhir
                } else {
                    $PARSED[$x][] = array(); // Tambahkan array kosong ke $PARSED[$x]
                    $CURRENT = &$PARSED[$x][count($PARSED[$x]) - 1]; // Mengakses array terakhir di dalam $PARSED[$x]
                }
            } elseif ($x != '!done') {
                $MATCHES = array();
                if (preg_match_all('/[^=]+/i', $x, $MATCHES)) {
                    if ($MATCHES[0][0] == 'ret') {
                        $singlevalue = $MATCHES[0][1];
                    }
                    $CURRENT[$MATCHES[0][0]] = (isset($MATCHES[0][1]) ? $MATCHES[0][1] : '');
                }
            }
        }

        if (!empty($PARSED)) {
            return $PARSED;
        } else {
            return array();
        }
    }

    public function read($parse = true)
    {
        $RESPONSE     = array();
        $receiveddone = false;
        while (true) {
            // Read the first byte of input which gives us some or all of the length
            // of the remaining reply.
            $BYTE   = ord(fread($this->socket, 1));
            $LENGTH = 0;
            // If the first bit is set then we need to remove the first four bits, shift left 8
            // and then read another byte in.
            // We repeat this for the second and third bits.
            // If the fourth bit is set, we need to remove anything left in the first byte
            // and then read in yet another byte.
            if ($BYTE & 128) {
                if (($BYTE & 192) == 128) {
                    $LENGTH = (($BYTE & 63) << 8) + ord(fread($this->socket, 1));
                } else {
                    if (($BYTE & 224) == 192) {
                        $LENGTH = (($BYTE & 31) << 8) + ord(fread($this->socket, 1));
                        $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                    } else {
                        if (($BYTE & 240) == 224) {
                            $LENGTH = (($BYTE & 15) << 8) + ord(fread($this->socket, 1));
                            $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                            $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                        } else {
                            $LENGTH = ord(fread($this->socket, 1));
                            $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                            $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                            $LENGTH = ($LENGTH << 8) + ord(fread($this->socket, 1));
                        }
                    }
                }
            } else {
                $LENGTH = $BYTE;
            }

            $_ = "";

            // If we have got more characters to read, read them in.
            if ($LENGTH > 0) {
                $_      = "";
                $retlen = 0;
                while ($retlen < $LENGTH) {
                    $toread = $LENGTH - $retlen;
                    $_ .= fread($this->socket, $toread);
                    $retlen = strlen($_);
                }
                $RESPONSE[] = $_;
                $this->debug('>>> [' . $retlen . '/' . $LENGTH . '] bytes read.');
            }

            // If we get a !done, make a note of it.
            if ($_ == "!done") {
                $receiveddone = true;
            }

            $STATUS = socket_get_status($this->socket);
            if ($LENGTH > 0) {
                $this->debug('>>> [' . $LENGTH . ', ' . $STATUS['unread_bytes'] . ']' . $_);
            }

            if ((!$this->connected && !$STATUS['unread_bytes']) || ($this->connected && !$STATUS['unread_bytes'] && $receiveddone)) {
                break;
            }
        }

        if ($parse) {
            $RESPONSE = $this->parseResponse($RESPONSE);
        }

        return $RESPONSE;
    }


    public function write($command, $param2 = true)
    {
        if (!$command) {
            return false;
        }

        $data = explode("\n", $command);
        foreach ($data as $com) {
            $com = trim($com);
            fwrite($this->socket, $this->encodeLength(strlen($com)) . $com);
            $this->debug('<<< [' . strlen($com) . '] ' . $com);
        }

        if (is_int($param2)) {
            fwrite($this->socket, $this->encodeLength(strlen('.tag=' . $param2)) . '.tag=' . $param2 . chr(0));
            $this->debug('<<< [' . strlen('.tag=' . $param2) . '] .tag=' . $param2);
        } elseif (is_bool($param2)) {
            fwrite($this->socket, ($param2 ? chr(0) : ''));
        }

        return true;
    }

    public function comm($com, $arr = array())
    {
        $this->write($com, empty($arr));

        foreach ($arr as $k => $v) {
            switch ($k[0]) {
                case "?":
                    $el = "$k=$v";
                    break;
                case "~":
                    $el = "$k~$v";
                    break;
                default:
                    $el = "=$k=$v";
                    break;
            }

            $last = next($arr) === false;
            $this->write($el, $last);
        }

        return $this->read();
    }

    /**
     *
     * @return mixed dataMikrotik mengembalikan array data interface, user, aktif netwatch status up/down
     * 
     */
    public function dataMikrotik()
    {
        $data = [];
        $interface = $this->comm("/interface/print");
        $user = $this->comm("/ip/hotspot/user/print");
        $userprofile = $this->comm("/ip/hotspot/user/profile/print");
        $aktif = $this->comm("/ip/hotspot/active/print");
        $netwatchup = $this->comm("/tool/netwatch/print",  ["?status" => "up"]);
        $netwatchdown = $this->comm("/tool/netwatch/print",  ["?status" => "down"]);
        $res = $this->comm("/system/resource/print");

        $data = [
            "interface" => $interface,
            "user" => $user,
            "userprofile" => $userprofile,
            "aktif" => $aktif,
            "netwatchUp" => $netwatchup,
            "netwatchDown" => $netwatchdown,
            "resource" => $res,

        ];
        return $data;
    }

    /**
     * Mengambil data dari perangkat MikroTik.
     *
     * @param string $section Bagian path yang ingin diambil data, example: ("ip/hotspot/user").
     * @param mixed ...$params Pasangan key-value, bisa lebih dari 1 key-value, example: ($section, "?coment", "nama comment", "?profile", "nama profile").
     * @return mixed Data yang diperoleh dari perangkat MikroTik.
     */
    public function getData($section, ...$params)
    {
        return $this->comm("/$section/print", $this->parseParams($params));
    }

    /**
     * Mengambil data user dari perangkat MikroTik.
     *
     * @param mixed ...$params Pasangan key-value untuk filter data.
     * @return mixed Data user yang diperoleh dari perangkat MikroTik.
     */
    public function getDataUser(...$params)
    {
        return $this->comm("/ip/hotspot/user/print", $this->parseParams($params));
    }

    /**
     * Mengambil data user aktif dari perangkat MikroTik.
     *
     * @param mixed ...$params Pasangan key-value untuk filter data.
     * @return mixed Data user aktif yang diperoleh dari perangkat MikroTik.
     */
    public function getDataActive(...$params)
    {
        return $this->comm("/ip/hotspot/active/print", $this->parseParams($params));
    }

    /**
     * Mengambil data user berdasarkan komentar dari perangkat MikroTik.
     *
     * @param string $params Komentar yang ingin dicari.
     * @return mixed Data user yang ditemukan berdasarkan komentar.
     */
    public function getDataUserbyComment($params)
    {
        return $this->comm("/ip/hotspot/user/print", ['?comment' => "$params"]);
    }

    /**
     * Mengambil data user berdasarkan profil dari perangkat MikroTik.
     *
     * @param string $params Profil yang ingin dicari.
     * @return mixed Data user yang ditemukan berdasarkan profil.
     */
    public function getDataUserbyProfile($params)
    {
        return $this->comm("/ip/hotspot/user/print", ['?profile' => "$params"]);
    }

    /**
     * Menghitung jumlah user aktif dari perangkat MikroTik.
     *
     * @return mixed Jumlah user aktif.
     */
    public function jumlahAktif()
    {
        return $this->comm("/ip/hotspot/active/print", ['count-only' => '']);
    }

    /**
     * Menghitung jumlah user berdasarkan profil dari perangkat MikroTik.
     *
     * @param string $params Profil yang ingin dihitung.
     * @return mixed Jumlah user berdasarkan profil.
     */
    public function countByProfile($params)
    {
        return $this->comm("/ip/hotspot/user/print", ['count-only' => '', '?profile' => $params]);
    }

    /**
     * Menghitung jumlah user berdasarkan komentar dari perangkat MikroTik.
     *
     * @param string $params Komentar yang ingin dihitung.
     * @return mixed Jumlah user berdasarkan komentar.
     */
    public function countByComment($params)
    {
        return $this->comm("/ip/hotspot/user/print", ['count-only' => '', '?comment' => $params]);
    }

    /**
     * Mengambil total voucher dari perangkat MikroTik.
     *
     * 
     * @return mixed Total voucher.
     */
    public function totalVoucher()
    {
        return $this->comm("/ip/hotspot/user/print", ['count-only' => '']);
    }

    /**
     * Menambahkan user baru ke perangkat MikroTik.
     *
     * @param string $name Nama pengguna baru.
     * @param string $password Kata sandi untuk pengguna baru.
     * @param string $profile Profil yang akan diberikan kepada pengguna baru.
     * @param mixed $param Parameter tambahan dalam bentuk array asosiatif (opsional).
     * @return mixed Hasil penambahan pengguna baru ke perangkat MikroTik.
     */
    public function addUser($name, $password, $profile, $param = '')
    {
        if (empty($name) || empty($password) || empty($profile)) {
            return false;
        }

        $parameters = ['name' => $name, 'password' => $password, 'profile' => $profile];
        if (!empty($param)) {
            $parameters = array_merge($parameters, $param);
        }

        return $this->comm("/ip/hotspot/user/add", $parameters);
    }

    /**
     * Menghapus pengguna dari perangkat MikroTik berdasarkan nama.
     *
     * @param string $name Nama pengguna yang akan dihapus.
     * @return mixed Hasil penghapusan pengguna dari perangkat MikroTik.
     */
    public function removeUser($name)
    {
        if (empty($name)) {
            return false;
        }

        $getId = $this->getDataUser("?name", "$name");
        $rowId = $getId[0]['.id'] ?? null;

        return $this->comm("/ip/hotspot/user/remove", ['.id' => $rowId]);
    }

    /**
     * Menghapus pengguna aktif dari perangkat MikroTik berdasarkan nama.
     *
     * @param string $name Nama pengguna aktif yang akan dihapus.
     * @return mixed Hasil penghapusan pengguna aktif dari perangkat MikroTik.
     */
    public function removeActive($name)
    {
        if (empty($name)) {
            return false;
        }

        $getId = $this->getDataActive("?user", "$name");
        $rowId = $getId[0]['.id'] ?? null;

        return $this->comm("/ip/hotspot/active/remove", ['.id' => "*$rowId"]);
    }

    /**
     * Menambahkan perangkat ke dalam daftar netwatch pada perangkat MikroTik.
     * Juga menambahkan alamat IP ke daftar ip-binding hotspot dengan komentar yang sama.
     * 
     * @param string $ip Alamat IP dari perangkat yang akan dimonitor.
     * @param string $comment Komentar yang akan digunakan untuk mengidentifikasi perangkat.
     * @param string|null $bot_token Token bot Telegram untuk pemberitahuan (opsional).
     * @param string|null $id_chat ID chat Telegram untuk pemberitahuan (opsional).
     * @return array|null Hasil penambahan perangkat ke dalam netwatch dan ip-binding hotspot.
     */
    public function addNetwatch($ip, $comment, $bot_token = null, $id_chat = null)
    {
        $netwatchResult = null;
        $hotspotResult = null;

        if ($bot_token !== null && $id_chat !== null) {
            $downScript = ':local hh $host; :local bot "' . $bot_token . '"; :local chat "' . $id_chat . '"; /tool fetch url="https://api.telegram.org/bot$bot/sendmessage\?chat_id=$chat&text=Alamat IP : ' . $ip . '%0ARouter : ' . $comment . '%0AStatus : MATI \E2\9D\8C" keep-result=no';
            $upScript = ':local hh $host; :local bot "' . $bot_token . '"; :local chat "' . $id_chat . '"; /tool fetch url="https://api.telegram.org/bot$bot/sendmessage\?chat_id=$chat&text=Alamat IP : ' . $ip . '%0ARouter : ' . $comment . '%0AStatus : ON \E2\9C\85" keep-result=no';
        } else {
            $downScript = "-";
            $upScript = "-";
        }

        $netwatchResult = $this->comm("/tool/netwatch/add", [
            "host" => $ip,
            "comment" => $comment,
            "down-script" => $downScript,
            "up-script" => $upScript
        ]);

        $hotspotResult = $this->comm("/ip/hotspot/ip-binding/add", [
            "address" => $ip,
            "to-address" => $ip,
            "type" => "bypassed",
            "comment" => $comment
        ]);

        return array("netwatch" => $netwatchResult, "hotspot" => $hotspotResult);
    }


    public function removeNetwatch($name)
    {
        if (empty($name)) {
            return false;
        }

        $getId = $this->getData("tool/netwatch", "?comment", $name);
        $rowId = $getId[0]['.id'] ?? null;

        $getId2 = $this->getData("ip/hotspot/ip-binding", "?comment", $name);
        $rowId2 = $getId2[0]['.id'] ?? null;

        // Hapus entri dari netwatch
        $response1 = $this->comm("/tool/netwatch/remove", ['.id' => $rowId]);

        // Hapus entri dari ip/hotspot/ip-binding
        $response2 = $this->comm("/ip/hotspot/ip-binding/remove", ['.id' => $rowId2]);

        // Gabungkan respons dari kedua operasi penghapusan
        return [$response1, $response2];
    }

    /**
     * Mengambil informasi resource dari perangkat MikroTik.
     *
     * @param string|null $params Nama resource yang ingin diambil informasinya.
     * @param mixed uptime Mengembalikan waktu hidup router jika diinginkan.
     * @param mixed version Mengembalikan versi MikroTik jika diinginkan.
     * @param mixed total-memory Mengembalikan total memori jika diinginkan.
     * @param mixed free-memory Mengembalikan memori yang tersedia jika diinginkan.
     * @param mixed cpu-oad Mengembalikan beban CPU jika diinginkan.
     * @param mixed board-name Mengembalikan nama papan jika diinginkan.
     * @return mixed getResources() Informasi resource dalam bentuk array jika tidak ada parameter yang ditentukan.
     *          
     */
    public function getResources($params = null)
    {
        $resources = $this->getData("system/resource");
        if ($params !== null) {
            return $resources[0][$params] ?? null;
        } else {
            return $resources[0] ?? null;
        }
    }

    /**
     *
     * @param string $param "up/down"  .
     * @return mixed Hasil netwacth berdasarkan status up atau down.
     */
    public function getNetwatch($param)
    {
        return $this->comm("/tool/netwatch/print",  ["?status" => $param]);
    }

    public function getScript(...$param)
    {

        return $this->comm("/system/script/print", $this->parseParams($param));
    }
    // Fungsi internal untuk memformat parameter sebelum mengirimkan permintaan ke perangkat MikroTik
    private function parseParams($params)
    {
        $requestData = [];
        for ($i = 0; $i < count($params); $i += 2) {
            if (isset($params[$i]) && isset($params[$i + 1])) {
                $key = $params[$i];
                $value = $params[$i + 1];
                $requestData["$key"] = "$value";
            }
        }
        return $requestData;
    }

    /**
     * Standard destructor
     *
     * @return void
     */
    public function __destruct()
    {
        $this->disconnect();
    }
}
?>

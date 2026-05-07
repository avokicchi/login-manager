<?php

namespace Avokicchi\LoginManager;

/**
 * Class LoginService
 *
 * Extended login module with cookie session restore
 */
class LoginService {

    private $_template;
    private $_cookieName = null;
    private $_cookiePath = null;
    private $_cookieDomain = '';
    private $_urlPath="/";
    private $_sessionLifetime=1800;
    private $_pdo=null;
	private $_extraCondition=null;

    private $_dbTable = "users";

    private $_dbFields = [
        "id" => "id",
        "username" => "username",
        "password" => "password"
    ];

    private $_inactivityTimeout = 7 * 24 * 60 * 60;//one week

    private $_debugLogs = false;
    private $_logPath = null;
    private $_requestId = null;

    /**
    * Instantiates the Login class.
    *
    * @param object $pdo            Database connection, \PDO object.
    * @param string $cookieName     name of your cookie.
    *
    * @return void
    */
    function __construct($pdo,$cookieName="_youridx") {
        $this->_pdo=$pdo;
        $this->_cookiePath = __DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."cache".DIRECTORY_SEPARATOR."sessions".DIRECTORY_SEPARATOR;//outside your publicly shared documentroot.
        $this->_cookieName = $cookieName;
        $this->_cookiePath=str_replace("\\", "/", $this->_cookiePath);
        if(!is_dir($this->_cookiePath)){
            @mkdir($this->_cookiePath,0777,true);
        }
        // Short per-request id so concurrent requests can be distinguished in the log.
        try {
            $this->_requestId = substr(bin2hex(random_bytes(4)), 0, 8);
        } catch (\Exception $e) {
            $this->_requestId = substr(md5(uniqid('', true)), 0, 8);
        }
    }

    /**
    * Enables/disables verbose logging to a file. Off by default.
    *
    * @param bool        $enabled  Turn logging on or off.
    * @param string|null $logPath  Optional absolute path to the log file. Defaults to
    *                              <cookiePath>/loginmanager.log (already outside the docroot).
    *
    * @return void
    */
    public function setDebugLogging($enabled, $logPath = null) {
        $this->_debugLogs = (bool)$enabled;
        if ($logPath !== null) {
            $this->_logPath = $logPath;
        }
    }

    /**
    * Appends one line to the debug log when debug logging is enabled. No-op otherwise.
    *
    * @param string $text  The message.
    *
    * @return void
    */
    private function logText($text) {
        if (!$this->_debugLogs) {
            return;
        }
        $path = $this->_logPath ?: ($this->_cookiePath . "loginmanager.log");
        $script = isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '-';
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '-';
        $pid = function_exists('getmypid') ? getmypid() : '-';
        $line = "[" . $this->_requestId . " " . date("Y-m-d H:i:s") . " pid=" . $pid . "] "
              . $script . " " . $uri . ": " . $text . "\n";
        //LOCK_EX so concurrent requests don't interleave mid-line.
        @file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
    }

    /**
    * Stores a key/value pair for the duration of your login session.
    *
    * @param string $key    The key
    * @param string $value  The value
    * 
    * @return void
    */
    public function set($key,$value) {
        if($this->isLoggedIn()) {
            $bag = $_SESSION['bag'];
            $_SESSION['bag'][$key] = $value;
            // There's only a cookie if Remember Me is on.
            if(isset($_COOKIE) && array_key_exists($this->_cookieName,$_COOKIE)) {
                $cookieHash = $_COOKIE[$this->_cookieName];
                $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
                $this->writeCookieData($cookieHash);
            }
        }
    }

    /**
    * Returns the value for a key for something you assigned with set()
    *
    * @param string $key    The key
    * 
    * @return mixed
    */
    public function get($key) {
        if($this->isLoggedIn()) {
            // Try to get from session, if not, then from cookie.
            $bag = isset($_SESSION['bag']) && !empty($_SESSION['bag']) && array_key_exists($key,$_SESSION['bag']) ? $_SESSION['bag'] : null;
            if(!empty($bag)) return $bag[$key];
            $cookieHash = array_key_exists($this->_cookieName,$_COOKIE) ? $_COOKIE[$this->_cookieName] : null;
            if(empty($cookieHash)) Return null;
            $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
            $cookieFile = $this->_cookiePath. $cookieHash . ".txt"; 
            if (file_exists($cookieFile)) {
                $data = unserialize(file_get_contents($cookieFile));
                $bag =  $data["bag"];
                return array_key_exists($key,$bag) ? $bag[$key] : null;
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

    /**
    * Allows overriding default database table name.
    *
    * @param string $tableName  New db table name
    * 
    * @return void
    */
    public function setUserTableName($tableName) {
        $tableName = preg_replace("/[^A-Za-z0-9]/", '', $tableName);
        $this->_dbTable=$tableName;
    }

    /**
    * Allows overriding default database field names if yours are different (email instead of username, pk instead of id, whatever)
    *
    * @param string $field  id|username|password
    * @param string $value  New db column name
    * 
    * @return bool
    */
    public function setUserField($field,$value) {
        $value = preg_replace("/[^A-Za-z0-9]/", '', $value);
        if(array_key_exists($field,$this->_dbFields)) {
            $this->_dbFields[$field]=$value;
            return true;
        } else {
            return false;
        }
    }
	
	/**
	* Add extra user condition
	*
	* If you need to add extra stuff to the condition to find a user
	* Use this function.
	*	
	* @param string $condition	Extra WHERE condition (without where or and)
	*
	*/
    public function setExtraCondition($condition) {
		$this->_extraCondition = $condition;
	}

    /**
    * Set inactivity timeout
    *
    * @param integer $timeout  Inactivity time (not accessing the website)in seconds after which the user should be logged out.
    * This value is also used to set the cookie lifetime. If used, it should be set before init.
    * 
    * @return void
    */
    public function setInactivityTimeout($timeout) {
        $this->_inactivityTimeout = $timeout;
    }

    /**
    * Function for extra secure pages. Determines whether your login is the result of a login, 
    * or by an extension of lifetime by a cookie, which is inherently less secure. 
    * You can use this to ask for an extra login action on an extra secure page.
    * 
    * @return bool
    */
    public function isLoginSecure() {
        return $this->isLoggedIn() && isset($_SESSION['secure']) && $_SESSION['secure'];
    }

    /**
    * Initializes login system, starts session, restore login from cookie, etc
    *
    * @param string $path  The ability to set a sub path where cookies apply to, like /account
    * 
    * @return void
    */
    public function init($path="/",$domain='') {
        $this->_urlPath=$path;
        $this->_cookieDomain=$domain;
        $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        // Start the session
        ini_set('session.cookie_lifetime', $this->_sessionLifetime);
        session_name('SESSID'.strtoupper($this->_cookieName));
	session_set_cookie_params(
	    $this->_sessionLifetime,
	    $path ?? '/',
	    $domain,
	    $secure,
	    $secure // httponly
	);
        session_start(['cookie_secure' => $secure,'cookie_httponly' => $secure,'cookie_path' => $path==null ? '/' : $path]);

        $this->logText("init() path=" . $path . " domain=" . $domain . " secure=" . ($secure ? '1' : '0')
            . " sessionId=" . session_id()
            . " hasRememberCookie=" . (isset($_COOKIE[$this->_cookieName]) ? '1' : '0')
            . " sessionUserId=" . (isset($_SESSION['user_id']) ? $_SESSION['user_id'] : 'unset'));
        //If user is not logged in with a session, but there is a cookie present,
        //Check if user is validly logged in using a cookie

        if (isset($_COOKIE[$this->_cookieName]) && !$this->isLoggedIn()) {
            // Get the hash from the cookie
            $cookieHash = $_COOKIE[$this->_cookieName];
            $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
            $cookieFile = $this->_cookiePath . $cookieHash . ".txt";

            $this->logText("cookie restore: attempting hash=" . $cookieHash);

            //Lock the cookie file to serialize concurrent requests. Without this, two requests
            //racing through init() could each delete the file and rotate the hash, causing one
            //of them to read "no file" -> getLastActivity returns false -> intval(false)=0 ->
            //treated as expired -> logout destroys the session for both.
            if (!file_exists($cookieFile)) {
                //File is gone (concurrent request already rotated it, or never existed).
                //Skip restoration rather than logging the user out.
                $this->logText("cookie restore: file does not exist for hash=" . $cookieHash . ", skipping (no logout)");
            } else {
                $fp = @fopen($cookieFile, 'r+');
                if ($fp === false || !flock($fp, LOCK_EX)) {//flock is blocking; concurrent requests queue up.
                    $this->logText("cookie restore: failed to open/lock file for hash=" . $cookieHash . ", skipping");
                    if ($fp) fclose($fp);
                } else {
                    $size = filesize($cookieFile);
                    $raw = $size > 0 ? fread($fp, $size) : '';
                    $data = @unserialize($raw);
                    //Track key presence separately from value: user_id=0 is a legitimate id in
                    //some apps, and PHP treats 0 as falsy. A truthy check would log
                    //out user 0 on every cookie restore.
                    $hasUser = is_array($data) && array_key_exists("user_id", $data);
                    $userId = $hasUser ? intval($data["user_id"]) : 0;
                    $lastActivity = is_array($data) && isset($data["last_activity"]) ? intval($data["last_activity"]) : 0;
                    $bag = is_array($data) && isset($data["bag"]) ? $data["bag"] : [];

                    $weekAgo = time() - $this->_inactivityTimeout;
                    $this->logText("cookie restore: hash=" . $cookieHash . " userId=" . $userId
                        . " lastActivity=" . $lastActivity . " weekAgo=" . $weekAgo
                        . " inactiveFor=" . (time() - $lastActivity) . "s"
                        . " bagSize=" . (is_array($bag) ? count($bag) : 0));

                    if ($lastActivity < $weekAgo) {
                        $this->logText("cookie restore: EXPIRED (lastActivity " . $lastActivity . " < " . $weekAgo . "), calling logout()");
                        flock($fp, LOCK_UN);
                        fclose($fp);
                        $this->logout();
                    } elseif ($hasUser) {
                        //Update last_activity in place, keep same hash. No rotation, no delete.
                        $newData = [
                            "user_id" => $userId,
                            "last_activity" => time(),
                            "bag" => $bag,
                        ];
                        ftruncate($fp, 0);
                        rewind($fp);
                        fwrite($fp, serialize($newData));
                        fflush($fp);
                        flock($fp, LOCK_UN);
                        fclose($fp);

                        //Restore session state directly instead of calling programmaticLogin,
                        //which would generate a new cookie hash and a new file.
                        $_SESSION['user_id'] = $userId;
                        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
                        $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
                        $_SESSION['bag'] = $bag;
                        $_SESSION['secure'] = false;

                        //Refresh the cookie expiration in the browser
                        setcookie($this->_cookieName, $cookieHash, time() + $this->_inactivityTimeout, $this->_urlPath, $this->_cookieDomain);
                        $this->logText("cookie restore: RESTORED userId=" . $userId . " hash=" . $cookieHash . " (no rotation)");
                    } else {
                        $this->logText("cookie restore: file had no valid userId for hash=" . $cookieHash . ", skipping");
                        flock($fp, LOCK_UN);
                        fclose($fp);
                    }
                }
            }
        }
        if(!$this->isLoggedIn()) {
            @session_regenerate_id();// regenerate session cookie with correct expiration. seems to work to resolve PHP assigning random session expiration times sometimes...
        }
    }

    /**
    * Sets the current error produced by verify()
    *
    * @param string       The error
    * 
    * @return void
    */
    private function setLastError($err) {
        $_SESSION['last_login_error']=$err;
    }

    /**
    * Gets the last error produced by verify()
    *
    * @return string       The error
    */
    public function getLastError() {
        return $_SESSION['last_login_error'];
    }

    /**
    * Generates a hash to store the cookie with
    *
    * @param int $userId   The user ID
    * 
    * @return string       The hash
    */
    private function generateCookieHash($userId) {
        $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $token = '';
        $max = mb_strlen($keyspace, '8bit') - 1;
        for ($i = 0; $i < 16; ++$i) {
            $token .= $keyspace[random_int(0, $max)];
        }
        return hash('sha256', $userId . $token);
    }

    /**
    * Retrieves the user's ID from the cookie
    *
    * @param string $cookieHash   The hash for the the cookie filename
    * 
    * @return int|bool            The user ID or false if the hash is invalid or the file doesn't exist
    */
    private function getUserIDFromCookie($cookieHash) {
        $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
        $cookieFile = $this->_cookiePath. $cookieHash . ".txt"; 
        if (file_exists($cookieFile)) {
            $data = unserialize(file_get_contents($cookieFile));
            return intval($data["user_id"]);
        } else {
            return false;
        }
    }

    /**
    * Retrieves the user's last activity timestamp from the cookie
    *
    * @param string $cookieHash     The hash for the the cookie filename
    * 
    * @return bool                  Whether something was removed or not.
    */
    private function clearCookie($cookieHash,$reason=null) {
        $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
        $cookieFile = $this->_cookiePath. $cookieHash . ".txt"; 
        if (file_exists($cookieFile)) {
            @unlink($cookieFile);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Retrieves the user's last activity timestamp from the cookie
     *
     * @param string $cookieHash   The hash for the the cookie filename
     * 
     * @return int|bool            The last activity timestamp or false if the hash is invalid or the file doesn't exist
     */
    private function getLastActivityFromCookie($cookieHash) {
        $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
        $cookieFile = $this->_cookiePath. $cookieHash . ".txt"; 
        if (file_exists($cookieFile)) {
            $data = unserialize(file_get_contents($cookieFile));
            return intval($data["last_activity"]);
        } else {
            return false;
        }
    }

    private function getBagFromCookie($cookieHash) {
        $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
        $cookieFile = $this->_cookiePath. $cookieHash . ".txt"; 
        if (file_exists($cookieFile)) {
            $data = unserialize(file_get_contents($cookieFile));
            return $data["bag"];
        } else {
            return false;
        }
    }

    /**
     * Saves the user's id and current time and key/value storage bag in a file on the server with the hash as the file name.
     *
     * @param string $cookieHash    The cookie hash
     * 
     * @return void
     */
    private function writeCookieData($cookieHash) {
        $userId=$_SESSION['user_id'];
        $data = [
            "user_id" => $userId,
            "last_activity" => time(),
            "bag" => isset($_SESSION['bag']) ? $_SESSION['bag'] : []
        ];
        $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
        $cookieFile = $this->_cookiePath. $cookieHash . ".txt";

        //Lock for the read-modify-write so concurrent set()/programmaticLogin() calls don't
        //clobber each other or leave the file half-written (which would unserialize to false and look like a missing/expired session
        $fp = @fopen($cookieFile, 'c+');
        if ($fp === false) {
            return;
        }
        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            return;
        }
        //Merge with any existing bag on disk so a concurrent set() in another request
        //isn't overwritten by our stale in-memory copy.
        $size = filesize($cookieFile);
        if ($size > 0) {
            rewind($fp);
            $existing = @unserialize(fread($fp, $size));
            if (is_array($existing) && isset($existing["bag"]) && is_array($existing["bag"])) {
                $data["bag"] = array_merge($existing["bag"], $data["bag"]);
            }
        }
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, serialize($data));
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
    }

    /**
    * Verifies a user's login details and returns success
    * 
    * @param string $username  The username
    * @param string $password  The password
    * 
    * @return bool
    */
    public function verify($username, $password) {
        // Query database for user with matching username
        $username=trim($username);
		
		$query = "SELECT * FROM ".$this->_dbTable." WHERE ".$this->_dbFields["username"]." = :username";
		if(!empty($this->_extraCondition)){
			$query = $query . " AND ".$this->_extraCondition;
		}
		
        $stmt = $this->_pdo->prepare($query);
        $stmt->execute([":username" => $username]);
        $user = $stmt->fetch(\PDO::FETCH_ASSOC);
        // Check if user was found
        if (!empty($user)) {
            // Verify password
            if (password_verify($password, $user[$this->_dbFields["password"]])) {
                // Password is correct
                return true;
            } else {
                // Password is incorrect
                $this->setLastError("Login details incorrect.");
                return false;
            }
        } else {
            // User not found
            $this->setLastError("User not found.");
            return false;
        }
    }

    /**
    * Gets a user's ID from their username.
    * 
    * @param string $username  The username
    * 
    * @return integer
    */
    private function getUserIdByUsername($username) {
        $username=trim($username);
        // Query the database for the user ID
		
		$query = "SELECT * FROM ".$this->_dbTable." WHERE ".$this->_dbFields["username"]." = :username";
		if(!empty($this->_extraCondition)){
			$query = $query . " AND ".$this->_extraCondition;
		}
		
        $stmt = $this->_pdo->prepare($query);
        $stmt->execute([":username" => $username]);
        $user = $stmt->fetch(\PDO::FETCH_ASSOC);
        // If the user was found, return the user ID
        if ($user) {
            return $user[$this->_dbFields["id"]];
        }
        // If the user was not found, return null
        return null;
    }

    /**
    * Verifies a passed username and password, and logs a user in, either with or without cookie login extension.
    * 
    * @param string $username   The username
    * @param string $password   The password
    * @param bool $rememberMe   Extend login lifetime using cookies.
    * 
    * @return bool
    */
    public function login($username, $password, $rememberMe) {
        $username=trim($username);
        // Verify the username and password
        if (!$this->verify($username, $password)) {
            return false;
        }
        // Get the user ID
        $user_id = $this->getUserIdByUsername($username);
        $this->programmaticLogin($user_id,$rememberMe);
        $_SESSION['secure'] = true;
        $_SESSION['bag'] = [];
        return true;
    }

    /**
    * Performs the actions that log the user in. Can also be used to programatically force a login, for instance if you implement security challenges with 2fa.
    * 
    * @param integer    $userId         The user's ID.
    * @param bool       $rememberMe     Extend login lifetime using cookies.
    * 
    * @return void
    */
    public function programmaticLogin($userId, $rememberMe) {
        $userId=(int)$userId;
        // Set session variables
        $_SESSION['user_id'] = $userId;
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
        // Set cookie
        if ($rememberMe) {
            $cookieHash = $this->generateCookieHash($userId);
            $this->writeCookieData($cookieHash);
            setcookie($this->_cookieName, $cookieHash, time() + $this->_inactivityTimeout, $this->_urlPath,$this->_cookieDomain);
            $this->logText("programmaticLogin: userId=" . $userId . " rememberMe=1 newHash=" . $cookieHash
                . " urlPath=" . $this->_urlPath . " domain=" . $this->_cookieDomain);
        } else {
            $this->logText("programmaticLogin: userId=" . $userId . " rememberMe=0 (no cookie set)");
        }
    }

    /**
    * Logs the user out.
    * 
    * @return void
    */
    public function logout() {
        if ($this->_debugLogs) {
            // Caller info so we know what triggered the logout (hijack check, expiry, explicit, etc.).
            $bt = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
            $caller = '<unknown>';
            if (isset($bt[1])) {
                $fn = isset($bt[1]['function']) ? $bt[1]['function'] : '?';
                $cl = isset($bt[1]['class']) ? $bt[1]['class'] : '';
                $ln = isset($bt[1]['line']) ? $bt[1]['line'] : (isset($bt[0]['line']) ? $bt[0]['line'] : '?');
                $caller = ($cl ? $cl . '::' : '') . $fn . ' line ' . $ln;
            }
            $this->logText("logout() called from " . $caller
                . " sessionUserId=" . (isset($_SESSION['user_id']) ? $_SESSION['user_id'] : 'unset')
                . " hasRememberCookie=" . (isset($_COOKIE[$this->_cookieName]) ? '1' : '0'));
        }
        // Clear session data
        $_SESSION = [];
        // Delete session cookie
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], 
            $params["domain"],
            $params["secure"], 
            $params["httponly"]
        );
        $cookieHash = is_array($_COOKIE) && array_key_exists($this->_cookieName,$_COOKIE) ? $_COOKIE[$this->_cookieName] :  null;
        if(!empty($cookieHash)) {
            $this->clearCookie($cookieHash,"logout");
        }
        // Delete remember me cookie
        setcookie($this->_cookieName, '', time() - 3600,$this->_urlPath,$this->_cookieDomain);
        // Destroy session
        session_destroy();
    }

    /**
    * Returns the user object associated with the login session.
    * 
    * @return mixed
    */
    public function getUser() {
        // Check if user is logged in
        if ($this->isLoggedIn()) {
            // Get user id from session
            $userId = $_SESSION['user_id'];
            // Query database for user details	
			
			$query = "SELECT * FROM ".$this->_dbTable." WHERE ".$this->_dbFields["id"]." = :user_id";
			if(!empty($this->_extraCondition)){
				$query = $query . " AND ".$this->_extraCondition;
			}
						
            $stmt = $this->_pdo->prepare($query);
            $stmt->execute([":user_id" => $userId]);
            $user = $stmt->fetch(\PDO::FETCH_ASSOC);
            // Return user details as associative array
            return $user;
        } else {
            // User is not logged in so return null
            return null;
        }
    }

    /**
    * Creates a user
    * 
    * @param string $username   The username
    * @param string $password   The password
    * 
    * @return integer|bool          Successful or not, if successful, a user id.
    */
    public function createUser($username,$password) {
        $stmt = $this->_pdo->prepare("INSERT INTO ".$this->_dbTable." (".$this->_dbFields["username"].",".$this->_dbFields["password"].") VALUES (:username,:password)");
        try {
            $stmt->execute([":username" => $username, ":password" => password_hash($password, PASSWORD_DEFAULT)]);
            return $this->_pdo->lastInsertId();
        } catch(\Throwable $e){
            return false;
        }
    }

    /**
    * Checks whether the user is logged in, and performs some security checks.
    * 
    * @return bool
    */
    public function isLoggedIn() {
        // Check if user ID is set in session
        if (isset($_SESSION['user_id'])) {
            // Verify user agent/ip
            if (isset($_SESSION['ip']) && $_SESSION['user_agent'] === $_SERVER['HTTP_USER_AGENT'] && $_SESSION['ip']===$_SERVER['REMOTE_ADDR']) {
                // User is logged in
                return true;
            } else {
                // User agent mismatch, possible session hijacking attempt
                $sessIp = isset($_SESSION['ip']) ? $_SESSION['ip'] : '<unset>';
                $sessUa = isset($_SESSION['user_agent']) ? $_SESSION['user_agent'] : '<unset>';
                $reqIp  = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '<unset>';
                $reqUa  = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '<unset>';
                $this->logText("isLoggedIn: HIJACK CHECK FAILED, calling logout()."
                    . " session.ip=" . $sessIp . " request.ip=" . $reqIp
                    . " session.ua=" . $sessUa . " request.ua=" . $reqUa);
                $this->logout();
            }
        }
        // User is not logged in
        return false;
    }

}

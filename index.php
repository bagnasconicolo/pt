<?php
/**************************************************************
 * index.php - Unified Router (Session + MySQL + Achievements + Comments)
 * -------------------------------------------------------------
 * MERGED from your two versions, preserving:
 *   - static pages
 *   - /auth/login & /auth/logout
 *   - /user (GET/POST) for statuses
 *   - /public/{username}, /publicinfo/{username}
 *   - /upload/{symbol}
 *   - /api/listusers
 *   - /settings
 *   - /api/medialist
 *   - /comments + /comments/count
 *   - Achievements awarding
 **************************************************************/
session_start();
require_once __DIR__ . '/db.php'; // $pdo

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

/** Return the current user_id from session or 0 */
function current_session_user_id() {
    return isset($_SESSION['user_id']) ? intval($_SESSION['user_id']) : 0;
}
function current_session_username() {
    return isset($_SESSION['username']) ? $_SESSION['username'] : null;
}
function require_login() {
    if (!current_session_user_id()) {
        http_response_code(403);
        echo json_encode(["status"=>"error","message"=>"Not logged in"]);
        exit;
    }
}

$request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method      = $_SERVER['REQUEST_METHOD'];

/**************************************************************
 * Serve static pages (GET)
 **************************************************************/
if ($method==='GET') {
    if ($request_uri==='/') {
        readfile("index.html");
        exit;
    } elseif ($request_uri==='/list') {
        readfile("list.html");
        exit;
    } elseif ($request_uri==='/profile') {
        readfile("profile.html");
        exit;
    } elseif ($request_uri==='/about') {
        readfile("about.html");
        exit;
    } elseif ($request_uri==='/usage') {
        readfile("usage.html");
        exit;
    } elseif ($request_uri==='/media') {
        readfile("media.html");
        exit;
    }
}

/**************************************************************
 * 1) AUTH: /auth/login, /auth/logout
 **************************************************************/
if ($method==='POST' && $request_uri==='/auth/login') {
    $body = json_decode(file_get_contents('php://input'), true);
    if (!$body || empty($body['username']) || empty($body['password'])) {
        http_response_code(400);
        echo json_encode(["status"=>"error","message"=>"Username/password required"]);
        exit;
    }
    $username = trim($body['username']);
    $password = $body['password'];

    // Attempt to find user
    $stmt = $pdo->prepare("SELECT id,password_hash FROM users WHERE username=?");
    $stmt->execute([$username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        // Auto-create user if doesn't exist
        $pw_hash = password_hash($password, PASSWORD_BCRYPT);
        $ins = $pdo->prepare("INSERT INTO users(username,password_hash,display_name) VALUES (?,?,?)");
        $ins->execute([$username, $pw_hash, $username]);
        $newId = $pdo->lastInsertId();
        $_SESSION['user_id']  = $newId;
        $_SESSION['username'] = $username;
        echo json_encode(["status"=>"success","message"=>"New user created, logged in"]);
        exit;
    }
    // Existing => verify password
    if (!password_verify($password, $row['password_hash'])) {
        http_response_code(403);
        echo json_encode(["status"=>"error","message"=>"Incorrect password"]);
        exit;
    }
    // Success => set session
    $_SESSION['user_id']  = $row['id'];
    $_SESSION['username'] = $username;
    echo json_encode(["status"=>"success","message"=>"Logged in"]);
    exit;
}
if ($method==='POST' && $request_uri==='/auth/logout') {
    session_destroy();
    echo json_encode(["status"=>"success","message"=>"Logged out"]);
    exit;
}

/**************************************************************
 * 2) PUBLIC VIEW: /public/{username}
 **************************************************************/
if ($method==='GET' && preg_match('/^\/public\/(.+)/', $request_uri, $m)) {
    $username = $m[1];
    $st = $pdo->prepare("SELECT id,public_listed FROM users WHERE username=?");
    $st->execute([$username]);
    $uRow = $st->fetch(PDO::FETCH_ASSOC);
    if (!$uRow) {
        http_response_code(404);
        echo json_encode(["status"=>"error","message"=>"User not found"]);
        exit;
    }
    if (!$uRow['public_listed']) {
        http_response_code(403);
        echo json_encode(["status"=>"error","message"=>"User is not public"]);
        exit;
    }
    $uid = $uRow['id'];
    // Load statuses
    $st2= $pdo->prepare("SELECT symbol,status,description,image_url,quantity,purity,is_wish,wishlist_priority
                         FROM statuses WHERE user_id=?");
    $st2->execute([$uid]);
    $statuses=[];
    while($r=$st2->fetch(PDO::FETCH_ASSOC)){
        $sym = $r['symbol'];
        $statuses[$sym] = [
            "status"      => $r['status'],
            "description" => $r['description'],
            "imageUrl"    => $r['image_url'],
            "quantity"    => (float)$r['quantity'],
            "purity"      => (float)$r['purity'],
            "isWish"      => (bool)$r['is_wish'],
            "wishlistPriority" => (int)$r['wishlist_priority']
        ];
    }
    echo json_encode(["status"=>"success","statuses"=>$statuses]);
    exit;
}

/**************************************************************
 * 3) PUBLICINFO: /publicinfo/{username}
 **************************************************************/
if ($method==='GET' && preg_match('/^\/publicinfo\/(.+)/', $request_uri, $m)) {
    $username = $m[1];
    $st = $pdo->prepare("SELECT display_name,bio,profile_image_url,public_listed
                         FROM users WHERE username=?");
    $st->execute([$username]);
    $row=$st->fetch(PDO::FETCH_ASSOC);
    if(!$row){
        http_response_code(404);
        echo json_encode(["status"=>"error","message"=>"User not found"]);
        exit;
    }
    if(!$row['public_listed']){
        http_response_code(403);
        echo json_encode(["status"=>"error","message"=>"User is not public"]);
        exit;
    }
    echo json_encode([
        "status"           => "success",
        "display_name"     => $row['display_name'],
        "bio"              => $row['bio'],
        "profile_image_url"=> $row['profile_image_url']
    ]);
    exit;
}

/**************************************************************
 * 4) Serve /uploads/* images
 **************************************************************/
if ($method==='GET' && preg_match('/^\/uploads\/(.+)/', $request_uri, $m)) {
    $filename = $m[1];
    $path = __DIR__."/uploads/".$filename;
    if(!file_exists($path)){
        http_response_code(404);
        echo "File not found";
        exit;
    }
    $mime = mime_content_type($path);
    header("Content-Type: $mime");
    readfile($path);
    exit;
}

/**************************************************************
 * 5) /api/listusers => list all public profiles
 **************************************************************/
if ($method==='GET' && $request_uri==='/api/listusers') {
    $stmt = $pdo->query("SELECT id,username,display_name FROM users WHERE public_listed=1");
    $users=[];
    while($u=$stmt->fetch(PDO::FETCH_ASSOC)){
        $uid=$u['id'];
        // count statuses
        $st2=$pdo->prepare("SELECT status FROM statuses WHERE user_id=?");
        $st2->execute([$uid]);
        $pure=0;
        $rep=0;
        $alloy=0;
        while($row=$st2->fetch(PDO::FETCH_ASSOC)){
            if($row['status']==='Pure')             $pure++;
            if($row['status']==='Representative')   $rep++;
            if($row['status']==='Alloy')            $alloy++;
        }
        $total=$pure+$rep+$alloy;
        $users[]=[
          "username"=>$u['username'],
          "display_name"=>$u['display_name'],
          "pure_count"=>$pure,
          "rep_count"=>$rep,
          "alloy_count"=>$alloy,
          "total_collected"=>$total
        ];
    }
    echo json_encode(["status"=>"success","users"=>$users]);
    exit;
}

/**************************************************************
 * PROTECTED ROUTES (must be logged in):
 *  - /user (GET/POST)
 *  - /upload/{symbol} (POST)
 *  - /settings (GET/POST)
 *  - /api/medialist
 *  - /comments + /comments/count
 **************************************************************/

// /user => GET => load, POST => save
if (preg_match('/^\/user$/',$request_uri)) {
    require_login();
    $uid = current_session_user_id();

    if($method==='GET'){
        // load statuses
        $st = $pdo->prepare("SELECT symbol,status,description,image_url,quantity,purity,is_wish,wishlist_priority,last_modified
                             FROM statuses WHERE user_id=?");
        $st->execute([$uid]);
        $statuses=[];
        $lm="";
        while($r=$st->fetch(PDO::FETCH_ASSOC)){
            $sym=$r['symbol'];
            $statuses[$sym]=[
              "status"=>$r['status'],
              "description"=>$r['description'],
              "imageUrl"=>$r['image_url'],
              "quantity"=>(float)$r['quantity'],
              "purity"=>(float)$r['purity'],
              "isWish"=>(bool)$r['is_wish'],
              "wishlistPriority"=>(int)$r['wishlist_priority']
            ];
            if($r['last_modified']>$lm) $lm=$r['last_modified'];
        }
        echo json_encode(["status"=>"success","statuses"=>$statuses,"last_modified"=>$lm]);
        exit;
    }
    elseif($method==='POST'){
        // save statuses
        $body=json_decode(file_get_contents('php://input'),true);
        if(!$body||!isset($body['statuses'])){
            http_response_code(400);
            echo json_encode(["status"=>"error","message"=>"Invalid input"]);
            exit;
        }
        $statuses=$body['statuses'];
        $ins = $pdo->prepare("
            INSERT INTO statuses (user_id, symbol, status, description, image_url, quantity, purity, is_wish, wishlist_priority, last_modified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
            ON DUPLICATE KEY UPDATE
                status = VALUES(status),
                description = VALUES(description),
                image_url = VALUES(image_url),
                quantity = VALUES(quantity),
                purity = VALUES(purity),
                is_wish = VALUES(is_wish),
                wishlist_priority = VALUES(wishlist_priority),
                last_modified = NOW()
        ");
        foreach($statuses as $sym=>$o){
            $sym   = substr($sym,0,5);
            $stat  = $o['status']       ?? '';
            $desc  = $o['description']  ?? '';
            $img   = $o['imageUrl']     ?? '';
            $qty   = floatval($o['quantity']??0);
            $purt  = floatval($o['purity']   ??100);
            $wish  = (!empty($o['isWish']) || $stat==='Wish')?1:0;
            $wprio = intval($o['wishlistPriority']??0);

            $ins->execute([$uid,$sym,$stat,$desc,$img,$qty,$purt,$wish,$wprio]);
        }
        // achievements
        checkAndAwardAchievements($pdo, $uid);
        echo json_encode(["status"=>"success","message"=>"Statuses updated"]);
        exit;
    }
}

// /upload/{symbol} => handle file upload
if($method==='POST' && preg_match('/^\/upload\/([^\/]+)/',$request_uri,$m)){
    require_login();
    $symbol=$m[1];
    $uid=current_session_user_id();
    $uname=current_session_username();

    if(!isset($_FILES['image'])||$_FILES['image']['error']!==UPLOAD_ERR_OK){
        http_response_code(400);
        echo json_encode(["status"=>"error","message"=>"No file or error"]);
        exit;
    }
    $max_file_size = 2*1024*1024;
    if($_FILES['image']['size']>$max_file_size){
        http_response_code(413);
        echo json_encode(["status"=>"error","message"=>"File too large (max 2MB)"]);
        exit;
    }
    $filename=basename($_FILES['image']['name']);
    $filename=preg_replace('/[^a-zA-Z0-9._-]/','_',$filename);
    $unique=$uname."_".$symbol."_".$filename;
    $dest=__DIR__."/uploads/".$unique;
    if(!move_uploaded_file($_FILES['image']['tmp_name'],$dest)){
        http_response_code(500);
        echo json_encode(["status"=>"error","message"=>"Failed to save file"]);
        exit;
    }
    if($symbol==='profile'){
        $st=$pdo->prepare("UPDATE users SET profile_image_url=? WHERE id=?");
        $st->execute(["/uploads/".$unique,$uid]);
    } else {
        $ins=$pdo->prepare("INSERT INTO statuses
           (user_id,symbol,status,description,image_url,quantity,purity,is_wish,wishlist_priority)
           VALUES(?,?,?,?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE image_url=VALUES(image_url), last_modified=NOW()");
        $ins->execute([$uid,$symbol,'','',"/uploads/".$unique,0,100,0,0]);
    }
    echo json_encode(["status"=>"success","imageUrl"=>"/uploads/".$unique]);
    exit;
}

// /settings => GET/POST profile
if(preg_match('/^\/settings$/',$request_uri)){
    $uid = current_session_user_id();
    if($method==='GET'){
        require_login();
        $stm=$pdo->prepare("SELECT username,display_name,email,bio,profile_image_url,public_listed
                            FROM users WHERE id=?");
        $stm->execute([$uid]);
        $row=$stm->fetch(PDO::FETCH_ASSOC);
        if(!$row){
            http_response_code(404);
            echo json_encode(["status"=>"error","message"=>"User data not found"]);
            exit;
        }
        echo json_encode(["status"=>"success","user"=>$row]);
        exit;
    }
    elseif($method==='POST'){
        require_login();
        $body=json_decode(file_get_contents('php://input'),true);
        if(!$body){
            http_response_code(400);
            echo json_encode(["status"=>"error","message"=>"No input"]);
            exit;
        }
        // fetch old pw
        $st=$pdo->prepare("SELECT password_hash FROM users WHERE id=?");
        $st->execute([$uid]);
        $urow=$st->fetch(PDO::FETCH_ASSOC);
        if(!$urow){
            http_response_code(404);
            echo json_encode(["status"=>"error","message"=>"User not found"]);
            exit;
        }
        // handle oldPassword => newPassword
        if(!empty($body['oldPassword']) && !empty($body['newPassword'])){
            if(!password_verify($body['oldPassword'],$urow['password_hash'])){
                http_response_code(403);
                echo json_encode(["status"=>"error","message"=>"Incorrect old password"]);
                exit;
            }
            $newHash=password_hash($body['newPassword'],PASSWORD_BCRYPT);
            $pdo->prepare("UPDATE users SET password_hash=? WHERE id=?")->execute([$newHash,$uid]);
        }
        // update other fields
        $dn=$body['display_name']??'';
        $em=$body['email']??'';
        $b =$body['bio']??'';
        $pl=!empty($body['public_listed'])?1:0;
        $pdo->prepare("UPDATE users SET display_name=?,email=?,bio=?,public_listed=? WHERE id=?")
            ->execute([$dn,$em,$b,$pl,$uid]);
        echo json_encode(["status"=>"success","message"=>"Profile updated"]);
        exit;
    }
}

// /api/medialist => GET => user images, DELETE => remove
if(preg_match('/^\/api\/medialist$/',$request_uri)){
    require_login();
    $uid=current_session_user_id();
    $uname=current_session_username();
    if($method==='GET'){
        $files=glob(__DIR__."/uploads/".$uname."_*");
        $res=[];
        foreach($files as $f){
            $base=basename($f);
            $res[]=["filename"=>$base,"url"=>"/uploads/".$base];
        }
        echo json_encode(["status"=>"success","files"=>$res]);
        exit;
    }
    elseif($method==='DELETE'){
        $body=json_decode(file_get_contents('php://input'),true);
        if(!$body||empty($body['filename'])){
            http_response_code(400);
            echo json_encode(["status"=>"error","message"=>"No filename"]);
            exit;
        }
        $filename=$body['filename'];
        if(strpos($filename,$uname."_")!==0){
            http_response_code(403);
            echo json_encode(["status"=>"error","message"=>"File not owned by user"]);
            exit;
        }
        $path=__DIR__."/uploads/".$filename;
        if(!file_exists($path)){
            http_response_code(404);
            echo json_encode(["status"=>"error","message"=>"File not found"]);
            exit;
        }
        unlink($path);
        echo json_encode(["status"=>"success","message"=>"File deleted"]);
        exit;
    }
}

/**************************************************************
 * COMMENTS /comments, plus /comments/count => show #comments
 **************************************************************/
if (preg_match('/^\/comments$/',$request_uri)) {
    if($method==='POST'){
        // {ownerUsername, symbol, commentText}
        $body=json_decode(file_get_contents('php://input'),true);
        if(!$body||empty($body['ownerUsername'])||empty($body['symbol'])||empty($body['commentText'])){
            http_response_code(400);
            echo json_encode(["status"=>"error","message"=>"Missing fields"]);
            exit;
        }
        $ownerUN = $body['ownerUsername'];
        $symbol  = $body['symbol'];
        $comment = $body['commentText'];

        // check owner user
        $st=$pdo->prepare("SELECT id,public_listed FROM users WHERE username=?");
        $st->execute([$ownerUN]);
        $oRow=$st->fetch(PDO::FETCH_ASSOC);
        if(!$oRow){
            http_response_code(404);
            echo json_encode(["status"=>"error","message"=>"Owner not found"]);
            exit;
        }
        if(!$oRow['public_listed']){
            http_response_code(403);
            echo json_encode(["status"=>"error","message"=>"Owner not public"]);
            exit;
        }
        $ownerId = $oRow['id'];
        $commenter = current_session_username() ?: 'Guest';
        $ins=$pdo->prepare("INSERT INTO comments(owner_user_id,symbol,commenter_username,comment_text)
                            VALUES(?,?,?,?)");
        $ins->execute([$ownerId,$symbol,$commenter,$comment]);
        echo json_encode(["status"=>"success","message"=>"Comment posted"]);
        exit;
    }
    elseif($method==='GET'){
        // /comments?ownerUsername=XX&symbol=YY
        $ownerUN=$_GET['ownerUsername']??'';
        $symbol=$_GET['symbol']??'';
        if(!$ownerUN||!$symbol){
            http_response_code(400);
            echo json_encode(["status"=>"error","message"=>"Must provide ownerUsername & symbol"]);
            exit;
        }
        $st=$pdo->prepare("SELECT id, public_listed FROM users WHERE username=?");
        $st->execute([$ownerUN]);
        $oRow=$st->fetch(PDO::FETCH_ASSOC);
        if(!$oRow || !$oRow['public_listed']){
            http_response_code(404);
            echo json_encode(["status"=>"error","message"=>"No public user found or user not public"]);
            exit;
        }
        $ownerId=$oRow['id'];
        $st2=$pdo->prepare("SELECT commenter_username,comment_text,created_at
                            FROM comments
                            WHERE owner_user_id=? AND symbol=?
                            ORDER BY created_at ASC");
        $st2->execute([$ownerId,$symbol]);
        $rows=$st2->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(["status"=>"success","comments"=>$rows]);
        exit;
    }
}
// /comments/count?ownerUsername=XX => returns { symbol => count, ...}
if($method==='GET' && preg_match('/^\/comments\/count$/',$request_uri)){
    $ownerUN=$_GET['ownerUsername']??'';
    if(!$ownerUN){
        http_response_code(400);
        echo json_encode(["status"=>"error","message"=>"Must provide ownerUsername"]);
        exit;
    }
    $st=$pdo->prepare("SELECT id,public_listed FROM users WHERE username=?");
    $st->execute([$ownerUN]);
    $oRow=$st->fetch(PDO::FETCH_ASSOC);
    if(!$oRow||!$oRow['public_listed']){
        http_response_code(404);
        echo json_encode(["status"=>"error","message"=>"No public user found or not public"]);
        exit;
    }
    $ownerId=$oRow['id'];
    // gather comment counts
    $st2=$pdo->prepare("SELECT symbol,COUNT(*) as cnt
                        FROM comments
                        WHERE owner_user_id=?
                        GROUP BY symbol");
    $st2->execute([$ownerId]);
    $counts=[];
    while($r=$st2->fetch(PDO::FETCH_ASSOC)){
        $counts[$r['symbol']] = (int)$r['cnt'];
    }
    echo json_encode(["status"=>"success","counts"=>$counts]);
    exit;
}

/**************************************************************
 * If no route matched
 **************************************************************/
http_response_code(404);
echo json_encode(["status"=>"error","message"=>"Invalid endpoint"]);

/**************************************************************
 * ACHIEVEMENTS
 **************************************************************/
function checkAndAwardAchievements(PDO $pdo, int $uid){
    // gather user statuses
    $st=$pdo->prepare("SELECT symbol,status FROM statuses WHERE user_id=?");
    $st->execute([$uid]);
    $collected=[];
    while($r=$st->fetch(PDO::FETCH_ASSOC)){
        // only count if status in {Pure,Alloy,Representative}
        if(in_array($r['status'],['Pure','Alloy','Representative'])){
            $collected[]=strtoupper($r['symbol']);
        }
    }
    $collected=array_unique($collected);

    // define sets
    $alkali = ['LI','NA','K','RB','CS','FR'];
    $nobles= ['HE','NE','AR','KR','XE','RN','OG'];
    $first10=['H','HE','LI','BE','B','C','N','O','F','NE'];

    // 1) All Alkali
    if(count(array_intersect($alkali,$collected))===count($alkali)){
        awardBadge($pdo,$uid,"All Alkali Metals");
    }
    // 2) All Noble Gases
    if(count(array_intersect($nobles,$collected))===count($nobles)){
        awardBadge($pdo,$uid,"All Noble Gases");
    }
    // 3) First 10
    $c10=0;
    foreach($first10 as $x){
        if(in_array($x,$collected)) $c10++;
    }
    if($c10===10){
        awardBadge($pdo,$uid,"First 10 Elements");
    }
}
function awardBadge(PDO $pdo,int $uid,string $badge){
    $st=$pdo->prepare("SELECT id FROM achievements WHERE user_id=? AND badge_name=?");
    $st->execute([$uid,$badge]);
    if(!$st->fetch()){
        $ins=$pdo->prepare("INSERT INTO achievements(user_id,badge_name) VALUES(?,?)");
        $ins->execute([$uid,$badge]);
    }
}

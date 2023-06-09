<?php

session_start();

if (isset($_SESSION['user_id'])) {
  header('Location: /prueba/welcome.php');
  exit();
}

require 'database.php';
  
function insert_login($conn, $resultado, $email)
{
    $fecha_hora = date('Y-m-d H:i:s');
    $ip_address = $_SERVER['REMOTE_ADDR'];
    $navegador = $_SERVER['HTTP_USER_AGENT'];
    $os_type = php_uname('s');

    $insert_login = $conn->prepare('INSERT INTO log_login (resultado, fecha_hora, email, ip, navegador, SO, validation)
                                   VALUES (:resultado, :fecha_hora, :email, :ip, :navegador, :SO, :validation)');
    $insert_login->bindValue(':resultado', $resultado);
    $insert_login->bindValue(':fecha_hora', $fecha_hora);
    $insert_login->bindValue(':email', $email);
    $insert_login->bindValue(':ip', $ip_address);
    $insert_login->bindValue(':navegador', $navegador);
    $insert_login->bindValue(':SO', $os_type);
    $insert_login->bindValue(':validation', 'encontrado');
    $insert_login->execute();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!empty($_POST['email']) && !empty($_POST['password'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];

    $records = $conn->prepare('SELECT users.id, users.email, users.password, roles.id AS role_id FROM users JOIN roles ON users.rol_id = roles.id WHERE users.email = :email');
    $records->bindParam(':email', $email);
    $records->execute();
    $results = $records->fetch(PDO::FETCH_ASSOC);

    $message = '';
    $login_status = 0;

    $navegador = $_SERVER['HTTP_USER_AGENT'];
    $os_type = php_uname('s');
    $ip_address = $_SERVER['REMOTE_ADDR'];

    // Verificar si la IP está bloqueada
    $blocked_attempts = $conn->prepare('SELECT login_attempt, block_end_time FROM failed_attempts WHERE email = :email');
    $blocked_attempts->bindParam(':email', $email);
    $blocked_attempts->execute();
    $blocked_info = $blocked_attempts->fetch(PDO::FETCH_ASSOC);

    if ($blocked_info && $blocked_info['login_attempt'] >= 3) {
      // Verificar si ha pasado el tiempo de bloqueo del correo
      if (strtotime($blocked_info['block_end_time']) > time()) {
        $remaining_time = strtotime($blocked_info['block_end_time']) - time();
        $message = 'Too many failed attempts. Please try again later. Remaining time: ' . gmdate('i:s', $remaining_time);
        insert_login($conn, 'fallido', $email);
      } else {
        // Desbloquear el correo
        $unblock_email = $conn->prepare('DELETE FROM failed_attempts WHERE email = :email');
        $unblock_email->bindParam(':email', $email);
        $unblock_email->execute();
        //$message = 'Please try again.';
      }
    } else {
      if (count($results) > 0 && password_verify($password, $results['password'])) {
        if (isset($_POST['g-recaptcha-response'])) {
          $secretKey = '6Lcn4NMlAAAAACOoBrUlFlTsER4D0i0G55tLDUEC';
          $captchaResponse = $_POST['g-recaptcha-response'];

          $url = 'https://www.google.com/recaptcha/api/siteverify';
          $data = array(
            'secret' => $secretKey,
            'response' => $captchaResponse
          );

          $options = array(
            'http' => array(
              'header' => "Content-type: application/x-www-form-urlencoded\r\n",
              'method' => 'POST',
              'content' => http_build_query($data)
            )
          );

          $context = stream_context_create($options);
          $verify = file_get_contents($url, false, $context);
          $captchaSuccess = json_decode($verify);

          if ($captchaSuccess->success) {
            $_SESSION['user_id'] = $results['id'];
            if ($results['role_id'] == 2) {
              $_SESSION['user_role'] = 'admin';
              header("Location: /prueba/admin.php");
            } else {
              $_SESSION['user_role'] = 'user';
              header("Location: /prueba/index.php");
            } 
            insert_login($conn, 'éxito', $email);
            exit();
          } else {
            $message = 'reCAPTCHA verification failed.';
            insert_login($conn, 'fallido', $email);
          }
        } else {
          $message = 'reCAPTCHA verification failed.';
          insert_login($conn, 'fallido', $email);
        }
      } else {
        $message = 'Invalid credentials.';
        insert_login($conn, 'fallido', $email);

        // Manejar intentos fallidos
        $failed_attempts = $conn->prepare('SELECT login_attempt FROM failed_attempts WHERE email = :email');
        $failed_attempts->bindParam(':email', $email);
        $failed_attempts->execute();
        $attempts_info = $failed_attempts->fetch(PDO::FETCH_ASSOC);



        if ($blocked_info) {
          // Incrementar el contador de intentos fallidos
          $login_attempt = $blocked_info['login_attempt'] + 1;

          if ($login_attempt >= 3) {
            // Bloquear el correo por 1 minuto
            $block_end_time = date('Y-m-d H:i:s', strtotime('+1 minute'));
            $update_attempts = $conn->prepare('UPDATE failed_attempts SET login_attempt = :login_attempt, block_end_time = :block_end_time WHERE email = :email');
            $update_attempts->bindParam(':login_attempt', $login_attempt);
            $update_attempts->bindParam(':block_end_time', $block_end_time);
            $update_attempts->bindParam(':email', $email);
            $update_attempts->execute();

            $message = 'Too many failed attempts. Please try again later. Remaining time: 1:00';
          } else {
            $update_attempts = $conn->prepare('UPDATE failed_attempts SET login_attempt = :login_attempt WHERE email = :email');
            $update_attempts->bindParam(':login_attempt', $login_attempt);
            $update_attempts->bindParam(':email', $email);
            $update_attempts->execute();

            $attempts_remaining = 3 - $login_attempt;
            $message = 'Sorry, those credentials do not match. Attempts remaining: ' . $attempts_remaining;
          }
        } else {
          // Registrar el intento fallido
          $insert_attempt = $conn->prepare('INSERT INTO failed_attempts (email, login_attempt, block_end_time) VALUES (:email, 1, DATE_ADD(NOW(), INTERVAL 1 MINUTE))');
          $insert_attempt->bindParam(':email', $email);
          $insert_attempt->execute();

          $message = 'Sorry, those credentials do not match. Attempts remaining: 2';
        }
      }

    }
  } else {
    $message = 'Please fill in both email and password fields.';
  }
}

?>


<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Login</title>
  <link href="https://fonts.googleapis.com/css?family=Roboto" rel="stylesheet">
  <link rel="stylesheet" href="assets/css/style.css">
  <script src="https://www.google.com/recaptcha/api.js" async defer></script>

  <style>
    body {
      font-family: 'Roboto', sans-serif;
      background-color: #3498db; /* Fondo azul */
    }
    
    .center {
      margin: auto;
      width: 300px;
      padding: 40px;
      background-color: #ffcccc; /* Cuadro rosa */
      border: 5px solid #ccc;
      border-radius: 10px;
      box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    }
    
    .center h1 {
      text-align: center;
    }
    
    .center span {
      display: block;
      text-align: center;
      margin-top: 10px;
    }
    
    .center form {
      margin-top: 20px;
    }
    
    .center input[type="text"],
    .center input[type="password"] {
      width: 100%;
      padding: 10px;
      margin-bottom: 10px;
      border: 1px solid #ccc;
      border-radius: 5px;
    }
    
    .center .g-recaptcha {
      margin-bottom: 10px;
    }
    
    .center input[type="submit"] {
      width: 100%;
      padding: 10px;
      background-color: #4caf50;
      color: #ffffff;
      border: none;
      border-radius: 5px;
      cursor: pointer;
    }
    
    .center input[type="submit"]:hover {
      background-color: #45a049;
    }
    
    .center p.error-message {
      color: #ff0000;
      text-align: center;
    }
  </style>
</head>
<body>
  <?php require 'partials/header.php' ?>
  <div class="center">
    <?php if (!empty($message)): ?>
      <p><?= $message ?></p>
    <?php endif; ?>

    <h1>Login</h1>
    <span>or <a href="signup.php">SignUp</a></span>

    <form action="login.php" method="POST">
      <input name="email" type="text" placeholder="Enter your email">
      <input name="password" type="password" placeholder="Enter your Password">
      <div class="g-recaptcha" data-sitekey="6Lcn4NMlAAAAADnx1irCKZ2Gs6gx0qCVO5wOVeNO"></div>
      <input id="submit-btn" type="submit" value="Submit">
    </form>
  </div>
</body>
</html>
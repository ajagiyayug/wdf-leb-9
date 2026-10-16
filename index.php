<?php
// Database Connection Configuration
$host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "user_system";

// Connection establish karein
$conn = new mysqli($host, $db_user, $db_pass);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Database create karein agar pehle se na ho
$conn->query("CREATE DATABASE IF NOT EXISTS $db_name");
$conn->select_db($db_name);

// Table create karein agar pehle se na ho
$tableQuery = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";
$conn->query($tableQuery);

$message = "";

// Form submit hone par logic
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['register'])) {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    // Server-side validation
    if (empty($username) || empty($email) || empty($password)) {
        $message = "<p style='color:red;'>All fields are required!</p>";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "<p style='color:red;'>Invalid email format!</p>";
    } else {
        // 1. Check duplicate username or email using Prepared Statement
        $checkStmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $checkStmt->bind_param("ss", $username, $email);
        $checkStmt->execute();
        $checkStmt->store_result();

        if ($checkStmt->num_rows > 0) {
            $message = "<p style='color:red;'>Error: Username or Email already exists!</p>";
        } else {
            // 2. Hash password securely
            $hashed_password = password_hash($password, PASSWORD_BCRYPT);

            // 3. Insert user into database
            $insertStmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $insertStmt->bind_param("sss", $username, $email, $hashed_password);

            if ($insertStmt->execute()) {
                $message = "<p style='color:green;'>Registration successful!</p>";
            } else {
                $message = "<p style='color:red;'>Something went wrong. Please try again.</p>";
            }
            $insertStmt->close();
        }
        $checkStmt->close();
    }
}
$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure User Registration</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); width: 350px; }
        h2 { text-align: center; color: #333; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; color: #666; font-size: 14px; }
        input { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007BFF; border: none; color: white; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { color: red; font-size: 12px; margin-top: 3px; display: block; }
        .msg-box { text-align: center; margin-top: 10px; }
    </style>
</head>
<body>

<div class="container">
    <h2>Register</h2>
    
    <!-- PHP Response Message Display -->
    <div class="msg-box">
        <?php echo $message; ?>
    </div>

    <form id="regForm" action="" method="POST" onsubmit="return validateForm()">
        <div class="form-group">
            <label>Username</label>
            <input type="text" id="username" name="username">
            <span id="usernameError" class="error"></span>
        </div>
        <div class="form-group">
            <label>Email</label>
            <input type="email" id="email" name="email">
            <span id="emailError" class="error"></span>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" id="password" name="password">
            <span id="passwordError" class="error"></span>
        </div>
        <button type="submit" name="register">Register</button>
    </form>
</div>

<script>
function validateForm() {
    let isValid = true;
    
    let username = document.getElementById('username').value.trim();
    let email = document.getElementById('email').value.trim();
    let password = document.getElementById('password').value.trim();

    // Clear previous errors
    document.getElementById('usernameError').innerText = '';
    document.getElementById('emailError').innerText = '';
    document.getElementById('passwordError').innerText = '';

    if (username === '') {
        document.getElementById('usernameError').innerText = 'Username is required';
        isValid = false;
    }

    if (email === '') {
        document.getElementById('emailError').innerText = 'Email is required';
        isValid = false;
    }

    if (password.length < 6) {
        document.getElementById('passwordError').innerText = 'Password must be at least 6 characters long';
        isValid = false;
    }

    return isValid;
}
</script>

</body>
</html>
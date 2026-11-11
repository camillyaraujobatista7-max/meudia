<?php
// XAMPP: usuário "root" sem senha (padrão). Ajuste se necessário.
session_start();
header('Content-Type: application/json; charset=utf-8');
mysqli_report(MYSQLI_REPORT_OFF);
$db = new mysqli('localhost', 'root', '', 'meudia');
if ($db->connect_error) { echo json_encode(['ok'=>false,'erro'=>'Sem conexão com o MySQL. Importe database.sql.']); exit; }
$db->set_charset('utf8mb4');
$in = json_decode(file_get_contents('php://input'), true) ?: [];
$a = $_GET['a'] ?? '';
$uid = $_SESSION['uid'] ?? 0;
function out($d){ echo json_encode($d); exit; }

if ($a === 'register' || $a === 'login') {
  $email = strtolower(trim($in['email'] ?? '')); $senha = $in['senha'] ?? '';
  if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($senha) < 4) out(['ok'=>false,'erro'=>'Informe um e-mail válido e senha com 4+ caracteres.']);
  if ($a === 'register') {
    $h = password_hash($senha, PASSWORD_DEFAULT);
    $s = $db->prepare('INSERT INTO users(email,senha) VALUES(?,?)'); $s->bind_param('ss', $email, $h);
    if (!$s->execute()) out(['ok'=>false,'erro'=>'Este e-mail já está cadastrado.']);
    $_SESSION['uid'] = $db->insert_id; out(['ok'=>true,'data'=>null]);
  }
  $s = $db->prepare('SELECT id,senha FROM users WHERE email=?'); $s->bind_param('s', $email); $s->execute();
  $u = $s->get_result()->fetch_assoc();
  if (!$u || !password_verify($senha, $u['senha'])) out(['ok'=>false,'erro'=>'E-mail ou senha incorretos.']);
  $_SESSION['uid'] = $u['id']; $a = 'load'; $uid = $u['id'];
}
if ($a === 'logout') { session_destroy(); out(['ok'=>true]); }
if (!$uid) out(['ok'=>false,'erro'=>'Sessão expirada.','sessao'=>false]);
if ($a === 'save') {
  $j = json_encode($in['data'], JSON_UNESCAPED_UNICODE);
  $s = $db->prepare('REPLACE INTO user_data(user_id,data) VALUES(?,?)'); $s->bind_param('is', $uid, $j); $s->execute();
  out(['ok'=>true]);
}
// load
$s = $db->prepare('SELECT data FROM user_data WHERE user_id=?'); $s->bind_param('i', $uid); $s->execute();
$r = $s->get_result()->fetch_assoc();
out(['ok'=>true,'data'=>$r ? json_decode($r['data'], true) : null]);

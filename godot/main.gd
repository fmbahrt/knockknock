## knockknock example: host a lobby or join one by its code, then chat over
## Godot's own ENet multiplayer, which takes over the punched port.
##
## Headless smoke test (see `just godot-smoke`):
##   godot --headless --path godot -- --host <server:port>
##   godot --headless --path godot -- --join <server:port> <lobby-id>
extends Control

const MAX_PLAYERS := 7
const SMOKE_HELLO := "hello from the smoke test"

var _server: LineEdit
var _code: LineEdit
var _status: Label
var _peers: Label
var _log: RichTextLabel
var _message: LineEdit

var _join_token := ""
var _verified := {} # host: peer id -> true once its join token checks out
var _headless := "" # "", "host" or "join"


func _ready() -> void:
	# A server run without a certificate writes a development CA; `just godot`
	# copies it here. Without it, the public CA roots are trusted.
	if FileAccess.file_exists("res://dev-ca.pem"):
		Knockknock.ca_file = "res://dev-ca.pem"

	Knockknock.lobby_opened.connect(_on_lobby_opened)
	Knockknock.joiner_incoming.connect(func(session): _say("A player is knocking (session %s)…" % session))
	Knockknock.joiner_connected.connect(func(session, address): _say("Session %s connected from %s" % [session, address]))
	Knockknock.joiner_failed.connect(func(session, reason): _say("Could not reach session %s: %s" % [session, reason]))
	Knockknock.join_ready.connect(_on_join_ready)
	Knockknock.join_failed.connect(_on_join_failed)
	Knockknock.server_lost.connect(func(): _say("Lost the rendezvous server; reconnecting (the game keeps running)"))
	Knockknock.server_restored.connect(func(): _say("Back on the rendezvous server"))
	Knockknock.lobby_changed.connect(_on_lobby_changed)
	Knockknock.error.connect(func(message): _say("Error: " + message))

	multiplayer.peer_connected.connect(_on_peer_connected)
	multiplayer.peer_disconnected.connect(_on_peer_disconnected)
	multiplayer.connected_to_server.connect(_on_connected_to_server)
	multiplayer.connection_failed.connect(func(): _say("ENet could not connect to the host"))

	var args := OS.get_cmdline_user_args()
	if args.size() >= 2 and args[0] == "--host":
		_start_headless("host")
		_host(args[1])
	elif args.size() >= 3 and args[0] == "--join":
		_start_headless("join")
		_join(args[1], args[2])
	else:
		_build_ui()


# ---- Lobby -----------------------------------------------------------------

func _host(server: String) -> void:
	_set_status("Opening a lobby on %s…" % server)
	Knockknock.host_lobby(server)


func _on_lobby_opened(lobby_id: String, local_port: int) -> void:
	# knockknock released the game port; ENet takes it over.
	var peer := ENetMultiplayerPeer.new()
	var err := peer.create_server(local_port, MAX_PLAYERS)
	if err != OK:
		_say("Could not start the ENet server on port %d: %s" % [local_port, error_string(err)])
		return
	multiplayer.multiplayer_peer = peer
	Knockknock.attach_host(peer.host)
	_set_status("Hosting lobby %s" % lobby_id)
	if _code:
		_code.text = lobby_id
	_say("Lobby %s is open; share the code." % lobby_id)
	if _headless:
		print("LOBBY ", lobby_id)


func _on_lobby_changed(lobby_id: String) -> void:
	# The server forgot the old lobby (e.g. it restarted); players already
	# here are unaffected, new ones need the new code.
	if _code:
		_code.text = lobby_id
	_set_status("Hosting lobby %s" % lobby_id)
	_say("The lobby code changed to %s; share the new one." % lobby_id)


func _join(server: String, lobby_id: String) -> void:
	_set_status("Joining %s…" % lobby_id.to_upper())
	Knockknock.join_lobby(server, lobby_id)


func _on_join_ready(address: String, port: int, join_token: String) -> void:
	# The path to the host is open; ENet connects over it from the same port.
	_join_token = join_token
	var peer := ENetMultiplayerPeer.new()
	var err := peer.create_client(address, port, 0, 0, 0, Knockknock.get_local_port())
	if err != OK:
		_say("Could not start the ENet client: %s" % error_string(err))
		return
	multiplayer.multiplayer_peer = peer
	_set_status("Connecting to the host at %s:%d…" % [address, port])


func _on_join_failed(reason: String) -> void:
	_set_status("Join failed")
	_say("Join failed: " + reason)
	if _headless:
		_finish(false)


# ---- Multiplayer -------------------------------------------------------------

func _on_connected_to_server() -> void:
	_set_status("Connected")
	# Prove we came through the lobby, not just found the port.
	_introduce.rpc_id(1, _join_token)
	if _headless == "join":
		_say_to_host.rpc_id(1, SMOKE_HELLO)


func _on_peer_connected(id: int) -> void:
	if multiplayer.is_server():
		_say("ENet peer %d connected; waiting for its join token" % id)


func _on_peer_disconnected(id: int) -> void:
	if _verified.erase(id):
		_broadcast("Player %d left" % id)


## Joiner → host: the join token from `join_ready`.
@rpc("any_peer", "reliable")
func _introduce(token: String) -> void:
	if not multiplayer.is_server():
		return
	var id := multiplayer.get_remote_sender_id()
	var enet := multiplayer.multiplayer_peer as ENetMultiplayerPeer
	if not Knockknock.verify_join(enet.get_peer(id), token):
		_say("Peer %d sent an invalid join token; disconnecting it" % id)
		enet.disconnect_peer(id)
		return
	_verified[id] = true
	_broadcast("Player %d joined" % id)


## Joiner → host: a chat line, relayed to everyone if the sender is verified.
@rpc("any_peer", "reliable")
func _say_to_host(text: String) -> void:
	var id := multiplayer.get_remote_sender_id()
	if multiplayer.is_server() and _verified.has(id):
		_broadcast("Player %d: %s" % [id, text])


## Host → players.
@rpc("authority", "reliable")
func _show_message(text: String) -> void:
	_on_message(text)


func _broadcast(text: String) -> void:
	for id in _verified:
		_show_message.rpc_id(id, text)
	_on_message(text)


func _on_message(text: String) -> void:
	_say(text)
	if _headless and text.ends_with(SMOKE_HELLO):
		# The joiner's hello went joiner → host → everyone over ENet.
		print("HOST GOT HELLO" if _headless == "host" else "JOIN GOT ECHO")
		_finish(true)


func _send_chat() -> void:
	var text := _message.text.strip_edges()
	if text.is_empty() or multiplayer.multiplayer_peer == null:
		return
	_message.clear()
	if multiplayer.is_server():
		_broadcast("Host: " + text)
	else:
		_say_to_host.rpc_id(1, text)


func _update_peers() -> void:
	if _peers == null:
		return
	var enet := multiplayer.multiplayer_peer as ENetMultiplayerPeer
	if enet == null or not multiplayer.is_server():
		_peers.text = ""
		return
	var lines := PackedStringArray()
	for id in _verified:
		var peer := enet.get_peer(id)
		if peer:
			var rtt := peer.get_statistic(ENetPacketPeer.PEER_ROUND_TRIP_TIME)
			lines.append("Player %d: %d ms" % [id, rtt])
	_peers.text = "\n".join(lines)


# ---- UI ------------------------------------------------------------------------

func _build_ui() -> void:
	var margin := MarginContainer.new()
	margin.set_anchors_preset(Control.PRESET_FULL_RECT)
	for side in ["left", "right", "top", "bottom"]:
		margin.add_theme_constant_override("margin_" + side, 16)
	add_child(margin)

	var column := VBoxContainer.new()
	column.add_theme_constant_override("separation", 8)
	margin.add_child(column)

	_server = LineEdit.new()
	_server.text = "127.0.0.1:7777"
	_server.placeholder_text = "rendezvous server (host:port)"
	column.add_child(_server)

	var row := HBoxContainer.new()
	column.add_child(row)
	var host_button := Button.new()
	host_button.text = "Host lobby"
	host_button.pressed.connect(func(): _host(_server.text))
	row.add_child(host_button)
	_code = LineEdit.new()
	_code.placeholder_text = "lobby code"
	_code.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	row.add_child(_code)
	var join_button := Button.new()
	join_button.text = "Join"
	join_button.pressed.connect(func(): _join(_server.text, _code.text))
	row.add_child(join_button)

	_status = Label.new()
	_status.text = "Host a lobby, or enter a code and join."
	column.add_child(_status)
	_peers = Label.new()
	column.add_child(_peers)

	_log = RichTextLabel.new()
	_log.size_flags_vertical = Control.SIZE_EXPAND_FILL
	_log.scroll_following = true
	column.add_child(_log)

	var chat := HBoxContainer.new()
	column.add_child(chat)
	_message = LineEdit.new()
	_message.placeholder_text = "message"
	_message.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	_message.text_submitted.connect(func(_text): _send_chat())
	chat.add_child(_message)
	var send := Button.new()
	send.text = "Send"
	send.pressed.connect(_send_chat)
	chat.add_child(send)

	var timer := Timer.new()
	timer.wait_time = 1.0
	timer.autostart = true
	timer.timeout.connect(_update_peers)
	add_child(timer)


func _set_status(text: String) -> void:
	if _status:
		_status.text = text


func _say(text: String) -> void:
	if _log:
		_log.append_text(text + "\n")
	print(text)


# ---- Headless smoke test ---------------------------------------------------------

func _start_headless(role: String) -> void:
	_headless = role
	get_tree().create_timer(30.0).timeout.connect(func():
		print("TIMEOUT")
		get_tree().quit(1))


func _finish(ok: bool) -> void:
	# Linger so the host's ENet stats reach the server's dashboard; the
	# joiner stays a little longer so its session is still there.
	var linger := 0.5
	if ok:
		linger = 7.0 if _headless == "host" else 8.0
	get_tree().create_timer(linger).timeout.connect(func(): get_tree().quit(0 if ok else 1))

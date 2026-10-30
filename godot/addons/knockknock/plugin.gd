@tool
extends EditorPlugin

const AUTOLOAD := "Knockknock"


func _enable_plugin() -> void:
	add_autoload_singleton(AUTOLOAD, "res://addons/knockknock/knockknock.gd")


func _disable_plugin() -> void:
	remove_autoload_singleton(AUTOLOAD)

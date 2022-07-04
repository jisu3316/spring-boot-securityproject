package com.jisu.securityproject.controller.user;


import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {
	
	@GetMapping(value="/messages")
	public String mypage() throws Exception {

		return "user/messages";
	}
	@PostMapping(value={"/api/messages"})
	@ResponseBody
	public ResponseEntity apiMessages() throws Exception {
		System.out.println("여기들어옴");
		return ResponseEntity.ok().body("ok");
	}
}

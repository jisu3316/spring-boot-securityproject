package com.jisu.securityproject.controller.user;


import com.jisu.securityproject.domain.Account;
import com.jisu.securityproject.domain.AccountDto;
import com.jisu.securityproject.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;
	@GetMapping(value = "/mypage")
	public String myPage() throws Exception {

		return "user/mypage";
	}

	@GetMapping("/users")
	public String createUser() {
		return "user/login/register";
	}

	@PostMapping("/users")
	public String createUser(AccountDto accountDto) {
		Account account =
				new Account(
						accountDto.getUsername()
						,accountDto.getPassword()
						,accountDto.getEmail()
						,accountDto.getAge()
						,accountDto.getRole()
				);

		userService.createUser(account);
		return "redirect:/";
	}
}

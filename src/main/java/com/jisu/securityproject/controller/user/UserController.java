package com.jisu.securityproject.controller.user;


import com.jisu.securityproject.domain.Account;
import com.jisu.securityproject.domain.AccountDto;
import com.jisu.securityproject.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
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
		System.out.println("getUsername = " + accountDto.getUsername());
		System.out.println("getEmail = " + accountDto.getEmail());
		System.out.println("getPassword = " + accountDto.getPassword());
		System.out.println("getAge = " + accountDto.getAge());
		System.out.println("getRole = " + accountDto.getRole());
		ModelMapper modelMapper = new ModelMapper();
		Account account =
				new Account(accountDto.getUsername()
						,accountDto.getPassword()
						,accountDto.getEmail()
						,accountDto.getAge()
						,accountDto.getRole());


		System.out.println("========================");
		System.out.println("getUsername22222 = " + account.getUsername());
		System.out.println("getPassword22222 = " + account.getPassword());
		System.out.println("getEmail2222 = " + account.getEmail());


		userService.createUser(account);
		return "redirect:/";
	}
}

package es.milfist.user;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@EnableGlobalMethodSecurity(prePostEnabled = true)
@RestController
public class UserController {

	private UserRepository userRepository;

	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public UserController(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
		this.userRepository = userRepository;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}

	@PostMapping("/users/")
	public void saveUsuario(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		userRepository.save(user);
	}

	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/users/")
	public List<User> getAllUsuarios() {
		return userRepository.findAll();
	}

	@GetMapping("/users/{username}")
	public User getUsuario(@PathVariable String username) {
		return userRepository.findByUsername(username);
	}

	@GetMapping("/users/wtf")
	public String helloWorld() {
		return "HelloWorld";
	}



}


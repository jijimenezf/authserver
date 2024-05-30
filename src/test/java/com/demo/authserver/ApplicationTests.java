package com.demo.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import({ SecurityConfig.class, TokenService.class })
class ApplicationTests {

	@Autowired
	MockMvc mvc;

	@Test
	void tokenWhenAnonymousThenStatusIsUnauthorized() throws Exception {
		this.mvc.perform(post("/oauth2/token")).andExpect(status().isUnauthorized());
	}

	@Test
	void tokenWithBasicThenGetToken() throws Exception {
		MvcResult result = this.mvc.perform(post("/oauth2/token")
						.with(httpBasic("cashcard-client", "secret")))
				.andExpect(status().isOk()).andReturn();

		assertThat(result.getResponse().getContentAsString()).isNotEmpty();
	}

	@Test
	void rootWhenUnauthenticatedThen401() throws Exception {
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void rootWithBasicStatusIsUnauthorized() throws Exception {
		this.mvc.perform(get("/")
				.with(httpBasic("cashcard-client", "secret")))
				.andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockUser
	public void rootWithMockUserIsOk() throws Exception {
		this.mvc.perform(get("/"))
				.andExpect(status().isOk());
	}

}

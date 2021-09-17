package com.appcity.app.zuul.autenticacion;

import java.util.Arrays;
import java.util.Base64;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@RefreshScope
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenStore(tokenStore());
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests().antMatchers("/api/autenticacion/oauth/token").permitAll()
				.antMatchers(HttpMethod.POST, "/api/registro/registro/crear", "/api/registro/registro/crearNuevo",
						"/api/registro/registro/confirmarSuscripcion/**", "/api/usuarios/users/crearUsuarios")
				.permitAll()
				
				// Autenticacion
				.antMatchers(HttpMethod.POST, "/api/autenticacion/autenticacion/arreglar")
				.hasAnyRole("ADMIN")
				
				// Usuarios
				.antMatchers(HttpMethod.GET, "/api/usuarios/users/listar", "/api/usuarios/roles/lista",
						"/api/usuarios/users/verUsuario/**", "/api/usuarios/users/encontrarUsuario/**",
						"/api/usuarios/users/file/downloadImage/**", "/api/usuarios/users/verRoleUsuario/**")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")
				.antMatchers(HttpMethod.GET, "/api/usuarios/users/editarPerfil/**",
						"/api/usuarios/users/verificarCodigo/**")
				.hasAnyRole("ADMIN", "USER")
				.antMatchers(HttpMethod.GET, "/api/usuarios/users/cedula")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.POST, "/api/usuarios/users/crear", "/api/usuarios/users/crearUsuariosRegistro")
				.hasAnyRole("ADMIN", "USER")
				.antMatchers(HttpMethod.PUT, "/api/usuarios/users/eliminarAdmin/**",
						"/api/usuarios/users/editarUbicacion/**", "/api/usuarios/users/editar/**",
						"/api/usuarios/users/file/uploadImage/**")
				.hasAnyRole("ADMIN", "USER")
				.antMatchers(HttpMethod.PUT, "/api/usuarios/users/roleModerator/**",
						"/api/usuarios/users/arreglarUsuario")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.DELETE, "/api/usuarios/users/eliminar/**")
				.hasAnyRole("INTERVENTOR")
				
				// Busqueda
				.antMatchers(HttpMethod.GET, "/api/busqueda/busqueda/buscar")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")
				.antMatchers(HttpMethod.POST, "/api/busqueda/busqueda/crear")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/busqueda/busqueda/editarProyecto", "/api/busqueda/busqueda/editarMuro", "/api/busqueda/busqueda/actualizarDatos")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/busqueda/busqueda/eliminarProyecto", "/api/busqueda/busqueda/eliminarMuro")
				.hasAnyRole("INTERVENTOR")
				
				// Estadistica
				.antMatchers(HttpMethod.GET, "/api/estadistica/estadistica/verEstadistica/**", "/api/estadistica/estadistica/verLikes/**", "/api/estadistica/estadistica/verDislikes/**", "/api/estadistica/estadistica/verVisualizacion/**", "/api/estadistica/estadistica/verEstadisticasUsuario/**")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")
				.antMatchers(HttpMethod.GET, "/api/estadistica/estadistica/export/excel/**")
				.hasAnyRole("ADMIN", "MODERATOR", "INTERVENTOR")
				.antMatchers(HttpMethod.POST, "/api/estadistica/estadistica/crearEna", "/api/estadistica/estadistica/arreglar")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/estadistica/estadistica/visualizaciones/**", "/api/estadistica/estadistica/obtenerEstadistica/**")
				.hasAnyRole("ADMIN", "USER")
				.antMatchers(HttpMethod.DELETE, "/api/estadistica/estadistica/borrarEstadisticas/**", "/api/estadistica/estadistica/borrarEstadisticasUsuario/**")
				.hasAnyRole("INTERVENTOR")
				
				// Muro
				.antMatchers(HttpMethod.GET, "/api/muro/muros/listar", "/api/muro/muros/buscar/**")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")
				.antMatchers(HttpMethod.POST, "/api/muro/muros/crear", "/api/muro/muros/crearProyectos")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/muro/muros/eliminarProyecto/**")
				.hasAnyRole("INTERVENTOR")
				.antMatchers(HttpMethod.DELETE, "/api/muro/muros/eliminarMuro/**")
				.hasAnyRole("INTERVENTOR")
				
				// Notificaciones
				.antMatchers(HttpMethod.GET, "/api/notificaciones/notificaciones/verNotificaciones/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.antMatchers(HttpMethod.GET, "/api/notificaciones/notificaciones/editarUsuario/**","/api/notificaciones/notificaciones/verificarCodigoUsuario/**","/api/notificaciones/notificaciones/revisarNotificacion/**")
				.hasAnyRole("ADMIN", "INTERVENTOR")
				.antMatchers(HttpMethod.POST, "/api/notificaciones/notificaciones/enviar")
				.hasAnyRole("ADMIN","MODERATOR")
				.antMatchers(HttpMethod.POST, "/api/notificaciones/notificaciones/crear", "/api/notificaciones/notificaciones/editEnabled", "/api/notificaciones/notificaciones/editEstado", "/api/notificaciones/notificaciones/registro"
						, "/api/notificaciones/notificaciones/suscripciones", "/api/notificaciones/notificaciones/inscripciones")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/notificaciones/enviarMensajeModerator/**")
				.hasAnyRole("ADMIN","MODERATOR")
				.antMatchers(HttpMethod.PUT, "/api/notificaciones/notificaciones/borrarNotificacion/**")
				.hasAnyRole("ADMIN","USER")
				.antMatchers(HttpMethod.PUT, "/api/notificaciones/notificaciones/cambiarNotificacion/**","/api/notificaciones/notificaciones/arreglarNotificaciones")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/notificaciones/notificaciones/eliminarCodigoUsuario/**")
				.hasAnyRole("INTERVENTOR")
				.antMatchers(HttpMethod.DELETE, "/api/notificaciones/notificaciones/eliminar")
				.hasAnyRole("INTERVENTOR")
				
				//PreguntasRespuestas
				.antMatchers(HttpMethod.GET, "/api/preguntasrespuestas/preguntasrespuestas/obtenerProyectoByNombre/**","/api/preguntasrespuestas/preguntasrespuestas/verPreguntas/**",
						"/api/preguntasrespuestas/preguntasrespuestas/verRespuestas/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.antMatchers(HttpMethod.POST, "/api/preguntasrespuestas/preguntasrespuestas/crear")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/preguntasrespuestas/preguntasrespuestas/respuestas/**",
						"/api/preguntasrespuestas/preguntasrespuestas/abrirCuestionario/**",
						"/api/preguntasrespuestas/preguntasrespuestas/respuestasPregunta/**",
						"/api/preguntasrespuestas/preguntasrespuestas/respuestaFinal/**")
				.hasAnyRole("ADMIN","USER")
				.antMatchers(HttpMethod.PUT, "/api/preguntasrespuestas/preguntasrespuestas/crearpreguntas/**")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.DELETE, "/api/preguntasrespuestas/preguntasrespuestas/borrarPreguntas/**")
				.hasAnyRole("INTERVENTOR")
				
				// Proyectos
				.antMatchers(HttpMethod.GET,  "/api/proyectos/proyectos/listar", "/api/proyectos/proyectos/descripcion/**",
						"/api/proyectos/proyectos/listarByMuro/**", "/api/proyectos/proyectos/obtenerProyectoByNombre/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.antMatchers(HttpMethod.GET,  "/api/proyectos/proyectos/verCreador/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "MODERATOR")
				.antMatchers(HttpMethod.GET,  "/api/proyectos/proyectos")
				.hasAnyRole("ADMIN", "INTERVENTOR")
				.antMatchers(HttpMethod.POST, "/api/proyectos/proyectos/crear")
				.hasAnyRole("ADMIN", "MODERATOR")
				.antMatchers(HttpMethod.PUT, "/api/proyectos/proyectos/visualizaciones/**")
				.hasAnyRole("USER", "ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/proyectos/proyectos/eliminarAdmin/**","/api/proyectos/proyectos/editEnabled/**","/api/proyectos/proyectos/editarProyectos/**")
				.hasAnyRole("MODERATOR", "ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/proyectos/proyectos/arreglarCreador")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.DELETE, "/api/proyectos/proyectos/eliminar/**")
				.hasAnyRole("INTERVENTOR")
				
				// Recomendaciones
				.antMatchers(HttpMethod.GET,  "/api/recomendacion/recomendaciones/ubicacionMuro/**",
						"/api/recomendacion/recomendaciones/ubicacionProyectos/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.antMatchers(HttpMethod.POST, "/api/recomendacion/recomendaciones/crear")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/recomendacion/recomendaciones/editarUbicacion/**",
						"/api/recomendacion/recomendaciones/editarBusqueda/**")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.DELETE, "/api/recomendacion/recomendaciones/eliminar/**")
				.hasAnyRole("INTERVENTOR")
				
				// Registro
				.antMatchers(HttpMethod.GET,  "/api/registro/registro/ver/**", "/api/registro/registro/contraseña")
				.hasAnyRole("ADMIN", "INTERVENTOR")
				
				// Suscripciones
				.antMatchers(HttpMethod.GET,  "/api/subscripciones/subscripciones/verificarInscripcion/**", "/api/suscripcionesretos/subscripciones/verComentarios/**",
						"/api/subscripciones/subscripciones/verificarCuestionario/**",
						"/api/subscripciones/subscripciones/revisarLikes/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.antMatchers(HttpMethod.GET,  "/api/subscripciones/subscripciones/obtenerProyectoByNombre/**")
				.hasAnyRole("ADMIN", "INTERVENTOR")
				.antMatchers(HttpMethod.POST, "/api/subscripciones/subscripciones/crear")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/subscripciones/subscripciones/inscripciones/**","/api/subscripciones/subscripciones/anularInscripciones/**",
						"/api/subscripciones/subscripciones/comentarios/**",
						"/api/subscripciones/subscripciones/inscribirCuestionario/**",
						"/api/subscripciones/subscripciones/likes/**")
				.hasAnyRole("USER", "ADMIN")
				.antMatchers(HttpMethod.PUT, "/api/subscripciones/suscripciones/arreglarSuscripciones")
				.hasAnyRole("ADMIN")
				.antMatchers(HttpMethod.DELETE, "/api/subscripciones/subscripciones/borrar/**")
				.hasAnyRole("INTERVENTOR")
				
				// Retos
				.antMatchers(HttpMethod.GET, 
						"/api/retos/retos/listar",
						"/api/retos/retos/listarNombre/**",
						"/api/suscripcionesretos/suscripciones/revisarLike/**",
						"/api/suscripcionesretos/suscripciones/revisarSuscripciones/**",
						"/api/suscripcionesretos/suscripciones/verNombre/**",
						"/api/estadisticaretos/estadistica/verIdeas/**")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")
				.antMatchers(HttpMethod.PUT, 
						"/api/suscripcionesretos/suscripciones/ponerComentarios/**",
						"/api/suscripcionesretos/suscripciones/darLike/**",
						"/api/suscripcionesretos/suscripciones/listar",
						"/api/suscripcionesretos/suscripciones/suscribirse/**", "/api/retos/retos/ponerIdeas/**")
				.hasAnyRole("ADMIN", "USER")
				.antMatchers("/api/interventor/**")
				.hasRole("INTERVENTOR")
				.antMatchers("/api/parametrizacion/**", "/api/retos/**", "/api/suscripcionesretos/**",
						"/api/estadisticaretos/**")
				.hasRole("ADMIN").anyRequest().authenticated().and().cors()
				.configurationSource(corsConfigurationSource());
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {

		CorsConfiguration corsConfig = new CorsConfiguration();
		corsConfig.setAllowedOrigins(Arrays.asList("*"));
		corsConfig.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS"));
		corsConfig.setAllowCredentials(true);
		corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfig);
		return source;
	}

	@Bean
	public FilterRegistrationBean<CorsFilter> corsFilter() {
		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<CorsFilter>(
				new CorsFilter(corsConfigurationSource()));
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return bean;
	}

	@Bean
	public JwtTokenStore tokenStore() {
		// TODO Auto-generated method stub
		return new JwtTokenStore(accesTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter accesTokenConverter() {
		JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
		tokenConverter.setSigningKey(Base64.getEncoder().encodeToString("codigo_secreto".getBytes()));
		return tokenConverter;
	}

}

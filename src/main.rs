use actix_cors::Cors;
use actix_web::{
    App, HttpServer,
    web::{self, Data},
};
use middleware::{
    config::JwtConfig,
    handlers::{login_handler, protected_handler},
    middlewares::JwtMiddleware,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let jwt_config = JwtConfig::new("secret".to_owned(), 2);

    let factory = move || {
        App::new()
            .app_data(Data::new(jwt_config.clone()))
            .wrap(
                Cors::default()
                    .allow_any_header()
                    .allow_any_origin()
                    .allow_any_method()
                    .max_age(3600)
                    .supports_credentials(),
            )
            .service(web::resource("/login").route(web::post().to(login_handler)))
            .service(
                web::resource("/protected")
                    .wrap(JwtMiddleware::new(jwt_config.clone()))
                    .route(web::get().to(protected_handler)),
            )
            .service(web::resource("/").to(|| async { "Hello!" }))
    };

    log::info!("Running on http://localhost:5000");

    HttpServer::new(factory).bind("0.0.0.0:5000")?.run().await?;

    Ok(())
}

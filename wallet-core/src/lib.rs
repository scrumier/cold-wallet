#![no_std]
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::geometry::Point;
use embedded_graphics::mono_font::{ascii::FONT_6X10, MonoTextStyle};
use embedded_graphics::text::Alignment::Center;
use embedded_graphics::text::Text;


#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AppState {
	Init,
	SetupNewWallet,
	EnterPin,
	Settings,
	PublicKeyGeneration,
	SendMoney,
	ReceiveMoney,
}

pub struct ColdWallet {
	pub state: AppState,
}

impl ColdWallet {
	pub fn new() -> Self {
		Self {
			state: AppState::Init,
		}
	}
	
	pub fn get_state(&self) -> AppState {
		self.state.clone()
	}
}


pub fn init_screen<D>(display: &mut D, animation_number: i32)
	-> Result<(), D::Error>
	where
		D: DrawTarget<Color=Rgb565>,
{
	let font = &FONT_6X10;
	let style = MonoTextStyle::new(font, Rgb565::WHITE);
	let position = Point::new(120, 120);
	
	match animation_number % 4 {
		0 => { Text::with_alignment("Loading |", position, style, Center).draw(display)?; }
		1 => { Text::with_alignment("Loading /", position, style, Center).draw(display)?; }
		2 => { Text::with_alignment("Loading -", position, style, Center).draw(display)?; }
		3 => { Text::with_alignment("Loading \\", position, style, Center).draw(display)?; }
		_ => { error_screen(display)?; }
	}
	
	
	Ok(())
}

pub fn error_screen<D>(display: &mut D)
	-> Result<(), D::Error>
	where
		D: DrawTarget<Color=Rgb565>,
{
	display.clear(Rgb565::RED)?;
	
	Ok(())
}

pub fn draw_ui<D>(display: &mut D, state: AppState, animation_number: i32)
	-> Result<(), D::Error>
	where
		D: DrawTarget<Color=Rgb565>,
{
	// Init black screen
	display.clear(Rgb565::BLACK)?;
	
	match state {
		AppState::Init => init_screen(display, animation_number)?,
		_ => error_screen(display)?,
	}
	
	
	Ok(())
}

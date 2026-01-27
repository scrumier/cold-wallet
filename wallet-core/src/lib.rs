#![no_std]
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Circle, Primitive, PrimitiveStyle};
use embedded_graphics::geometry::Point;


pub fn draw_ui<D>(display: &mut D)
	-> Result<(), D::Error>
	where
		D: DrawTarget<Color=Rgb565>,
{
	// Init black screen
	display.clear(Rgb565::BLACK)?;
	
	// Draw red circle
	let style = PrimitiveStyle::with_fill(Rgb565::RED);
	Circle::with_center(Point::new(120, 120), 50)
		.into_styled(style)
		.draw(display)?;
	
	Ok(())
}

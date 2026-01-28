use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics_simulator::{SimulatorDisplay, Window, OutputSettingsBuilder};
use wallet_core::{draw_ui, ColdWallet};
use embedded_graphics::geometry::Size;


fn main()
	-> Result<(), Box<dyn std::error::Error>>
{
	// Init screen
	let screen_size = Size::new(240, 240);
	let mut display = SimulatorDisplay::<Rgb565>::new(screen_size);
	
	// Init wallet
	let wallet = ColdWallet::new();
	
	let mut tick_counter = 0;
	let mut animation_number = 0;
	let mut update = false;
	
	display.clear(Rgb565::BLACK)?;
	
	// Settings for MacOS
	let output_settings = OutputSettingsBuilder::new().scale(2)
	                                                  .build();
	let mut window = Window::new("Cold wallet", &output_settings);
	
	
	// Window loop
	'running: loop {
		window.update(&display);
		if update == true {
			draw_ui(&mut display, wallet.state, animation_number)?;
			animation_number += 1;
		}
		if window.events()
		         .any(|e| e == embedded_graphics_simulator::SimulatorEvent::Quit) {
			break 'running;
		}
		std::thread::sleep(std::time::Duration::from_millis(1000));
		
		if tick_counter % 100 == 1 {
			update = true;
		}
		tick_counter += 1;
	}
	
	
	Ok(())
}
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics_simulator::{SimulatorDisplay, Window, OutputSettingsBuilder};
use wallet_core::draw_ui;
use embedded_graphics::geometry::Size;


fn main()
	-> Result<(), Box<dyn std::error::Error>>
{
	// Init screen
	let screen_size = Size::new(240, 240);
	let mut display = SimulatorDisplay::<Rgb565>::new(screen_size);
	
	
	draw_ui(&mut display)?;
	
	
	// Settings for MacOS
	let output_settings = OutputSettingsBuilder::new().scale(2).build();
	let mut window = Window::new("Cold wallet", &output_settings);
	
	// Window loop
	'running: loop {
		window.update(&display);
		if window.events().any(|e| e == embedded_graphics_simulator::SimulatorEvent::Quit) {
			break 'running;
		}
		std::thread::sleep(std::time::Duration::from_millis(1000));
	}
	
	
	Ok(())
}
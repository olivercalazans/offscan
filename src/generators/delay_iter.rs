use rand::Rng;
use crate::utils::abort;



enum DelayMode {
    Fixed(f32),
    Random { min: f32, max: f32 },
}



pub(crate) struct DelayIter {
    mode      : DelayMode,
    remaining : usize,
}



impl DelayIter {

    pub fn new(delay_arg: &str, quantity: usize) -> Self {
        let mode = if delay_arg.contains('-') {
            let parts: Vec<&str> = delay_arg.split('-').collect();
            if parts.len() != 2 {
                abort(format!("Invalid delay range: {}", delay_arg));
            }

            let min = Self::validate_number(parts[0]);
            let max = Self::validate_number(parts[1]);

            if min >= max {
                abort(format!("Invalid delay range: {} (min >= max)", delay_arg));
            }

            DelayMode::Random { min, max }
        } else {
            let value = Self::validate_number(delay_arg);
            DelayMode::Fixed(value)
        };

        Self { mode, remaining: quantity, }
    }



    fn validate_number(number_str: &str) -> f32 {
        number_str.parse().unwrap_or_else(|_| {
            abort(format!("Invalid number: {}", number_str));
        })
    }

}



impl Iterator for DelayIter {
    
    type Item = f32;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;

        match self.mode {
            DelayMode::Fixed(value) => Some(value),
            DelayMode::Random { min, max } => {
                let mut rng = rand::thread_rng();
                Some(rng.gen_range(min..=max))
            }
        }
    }



    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }

}
package dio.security.ui

import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import dio.security.crypto.DropdownOption

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun <T: DropdownOption> DropdownSelector(
	label: String,
	options: List<T>,
	selectedOption: T,
	onOptionSelected: (T) -> Unit,
	modifier: Modifier = Modifier
) {
	var expanded by remember { mutableStateOf(false) }
	ExposedDropdownMenuBox(
		expanded = expanded,
		onExpandedChange = { expanded = !expanded },
		modifier = modifier
	) {
		TextField(
			readOnly = true,
			value = selectedOption.displayName(),
			onValueChange = {},
			label = { Text(label) },
			trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
			modifier = Modifier.Companion.menuAnchor()
		)
		DropdownMenu(
			expanded = expanded,
			onDismissRequest = { expanded = false }
		) {
			options.forEach { option ->
				DropdownMenuItem(
					text = { Text(option.displayName()) },
					onClick = {
						onOptionSelected(option)
						expanded = false
					}
				)
			}
		}
	}
}
package dio.security.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dio.security.crypto.Algorithm
import dio.security.crypto.DigestSize

@Composable
fun KeyAndAlgorithmDropdowns(
	algorithms: List<Algorithm>,
	digestSizes: List<DigestSize>,
	selectedDigestSize: DigestSize,
	selectedAlgorithm: Algorithm,
	onSelectedKeySize: (DigestSize) -> Unit,
	onSelectedAlgorithm: (Algorithm) -> Unit
) {
	Row(
		modifier = Modifier.fillMaxWidth(),
		horizontalArrangement = Arrangement.spacedBy(16.dp)
	) {
		DropdownSelector(
			label = "Algorithm",
			options = algorithms,
			selectedOption = selectedAlgorithm,
			onOptionSelected = onSelectedAlgorithm,
			modifier = Modifier.weight(1f)
		)

		DropdownSelector(
			label = "Digest size",
			options = digestSizes,
			selectedOption = selectedDigestSize,
			onOptionSelected = onSelectedKeySize,
			modifier = Modifier.weight(1f)
		)
	}
}
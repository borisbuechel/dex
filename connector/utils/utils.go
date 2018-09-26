package utils

// AppendAll merge to slices
func AppendAll(original []string, toAppend []string) []string {
	returnString := []string{}
	for _, entry := range original {
		returnString = append(returnString, entry)
	}
	for _, entry := range toAppend {
		returnString = append(returnString, entry)
	}
	return returnString
}

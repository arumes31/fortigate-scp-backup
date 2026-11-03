package reportmodel

// The catalog advertises actual configuration views separately from data
// families which cannot be generated from configuration backups.
type DatasetColumn struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	LabelDE string `json:"label_de"`
	Type    string `json:"type"`
}

type DatasetDefinition struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	NameDE        string          `json:"name_de"`
	Description   string          `json:"description"`
	DescriptionDE string          `json:"description_de"`
	Status        string          `json:"status"`
	Source        string          `json:"source"`
	Columns       []DatasetColumn `json:"columns"`
	RequiredData  []string        `json:"required_data"`
}

type Capability struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	NameDE        string   `json:"name_de"`
	Description   string   `json:"description"`
	DescriptionDE string   `json:"description_de"`
	Status        string   `json:"status"`
	Requirements  []string `json:"requirements"`
	Datasets      []string `json:"datasets"`
	SourceURL     string   `json:"source_url"`
}

// DatasetDefinitions documents the bounded built-in data contract. No custom
// SQL is executed, and unavailable log datasets are never fabricated.
func DatasetDefinitions() []DatasetDefinition {
	return datasetDefinitions()
}

func Capabilities() []Capability {
	return capabilityDefinitions()
}

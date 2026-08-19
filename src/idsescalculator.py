import flet as ft
from src.idsesutilities import Protocols, RiskEnvironment, RiskCriticality
from src.ivssvulnerability import IVSSVulnerability

class IDSESDevice:
    def __init__(self, name:str = "Unnamed", manufacturer:str = "N/A", year:int = 1970):
        self.protocols = {}
        self.vulnerabilities = {}
        self.score = 0.0
        self.update_information(name, manufacturer, year)

    def update_information(self, name:str = "Unnamed", manufacturer:str = "N/A", year:int = 1970, risk_environment:RiskEnvironment = RiskEnvironment.PERSONAL, risk_criticality:RiskCriticality = RiskCriticality.LOW):
        self.name = name
        self.vendor = manufacturer
        self.year = year
        self.risk_environment = risk_environment
        self.risk_criticality = risk_criticality

    def add_protocol(self, protocol:Protocols):
        self.protocols[protocol] = protocol.value

    def add_vulnerability(self, vulnerability:IVSSVulnerability):
        self.vulnerabilities[vulnerability] = vulnerability.get_name()

    def remove_protocol(self, protocol:Protocols):
        if protocol in self.protocols:
            del self.protocols[protocol]

    def remove_vulnerability(self, vulnerability:IVSSVulnerability):
        vuln_name = vulnerability.get_name()
        if vuln_name in self.vulnerabilities:
                del self.vulnerabilities[vuln_name]


class IDSESMainTab:
    def __init__(self, page):
        self.page = page
        self.device = IDSESDevice()

    def update_widget(self):
        self.ivss_widget.update_widget(self.impact_group, self.exposure_group, self.weights, False)

    def on_weight_change(self, category:str, new_weight:float):
        self.weights[category] = new_weight
        self.update_widget()

    async def ivss_str_to_clipboard(self):
        ivss_vector_string = IVSSStringVectorUtil.get_ivss_str(self.impact_group, self.exposure_group)
        await ft.Clipboard().set(ivss_vector_string)
        self.page.show_dialog(ft.SnackBar("Text copied to clipboard"))

    def on_enter_cvss_vector_string(self, event:ft.Event[ft.TextField]):
        self.cvss_ivss_widget.update_widget_from_score(IVSSCalculator.get_ivss_score_from_cvss_vector(event.control.value))

    def populate(self) -> ft.Container:
        return ft.Container(
            alignment = ft.Alignment.CENTER,
            content= ft.Tabs(
                length=2,
                expand=True,
                content=ft.Column(
                    controls = [
                        ft.TabBar(
                            secondary=True,
                            tabs=[
                                ft.Tab(label=ft.Text("Vulnerability Score Calculator")),
                                ft.Tab(label=ft.Text("CVSS to IVSS Converter"))
                            ]
                        ),
                        ft.TabBarView(
                            expand=True,
                            controls=[
                                ft.Row(
                                    spacing = 10,
                                    controls=[
                                        ft.Column(
                                            margin = 15,
                                            spacing = 15,
                                            scroll = ft.ScrollMode.AUTO,
                                            controls = [
                                                ft.Row(
                                                    controls=[
                                                        ft.Text("Impact Group", size=36, weight=ft.FontWeight.W_800),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Confidentiality", self.impact_group, self).populate(),
                                                        IVSSCategory("Integrity", self.impact_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                    spacing = 50,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Availability", self.impact_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        ft.Text("Exposure Group", size=36, weight=ft.FontWeight.W_800),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Authentication", self.exposure_group, self).populate(),
                                                        IVSSCategory("Non-Repudiation", self.exposure_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                    spacing = 50,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Access", self.exposure_group, self).populate(),
                                                        IVSSCategory("Complexity", self.exposure_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                    spacing = 50,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Safety", self.exposure_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START
                                                ),
                                            ]
                                        ),
                                        ft.Column(
                                            margin = 15,
                                            spacing = 15,
                                            controls = [
                                                self.ivss_widget.populate(),
                                                ft.Button("Copy to clipboard", on_click=self.ivss_str_to_clipboard),
                                            ]
                                        )
                                    ],
                                ),
                                ft.Row(
                                    controls=[
                                        ft.Column(
                                            alignment=ft.MainAxisAlignment.CENTER,
                                            margin=15,
                                            controls=[
                                                self.cvss_ivss_widget.populate(False),
                                                ft.Button("Copy to clipboard", on_click=self.ivss_str_to_clipboard)
                                            ]
                                        ),
                                        ft.TextField(label="CVSS Vector String", hint_text="Enter a CVSS Vector String here...", on_submit=self.on_enter_cvss_vector_string)
                                    ],
                                    alignment=ft.MainAxisAlignment.CENTER
                                ),
                            ]
                        )
                    ]
                )
            )
        )
    
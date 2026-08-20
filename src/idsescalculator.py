import flet as ft
from src.idsesutilities import Protocols, RiskEnvironment, RiskCriticality
from src.ivsscalculator import IVSSMainTab, IVSSWidget
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
        self.checkboxes = []
        self.vulnerability_widgets = []
        self.ivss_main_tab = IVSSMainTab(page, True)
        self.ivss_editor = self.ivss_main_tab.populate()

        for p in Protocols: 
            self.checkboxes.append(ft.Checkbox(label=p.value[0], value=False, data=p.value[1]))

    def add_vulnerability_prompt(self):
        self.vulnerability_widgets.append(IVSSWidget(vulnerability=self.ivss_main_tab.export_vulnerability_and_reset_calculator()).create_widget())
        self.page.update()

    def populate(self) -> ft.Container:
        checkboxes_split_point = round(len(self.checkboxes)/2)
        return ft.Container(
            alignment = ft.Alignment.CENTER,
            content= ft.Row(
                spacing = 5,
                controls=[
                    ft.Column(
                        margin = 15,
                        spacing = 15,
                        scroll = ft.ScrollMode.AUTO,
                        controls=[
                            ft.Row(
                                controls=[
                                    ft.Text("Communications Protocols", size=36, weight=ft.FontWeight.W_800),
                                ],
                                alignment=ft.MainAxisAlignment.START,
                            ),
                            ft.Row(
                                controls=self.checkboxes[:checkboxes_split_point],
                                alignment=ft.MainAxisAlignment.START,
                            ),
                            ft.Row(
                                controls=self.checkboxes[checkboxes_split_point:],
                                alignment=ft.MainAxisAlignment.START,
                            ),
                            ft.Row(
                                controls=[
                                    ft.Text("Vulnerabilities", size=36, weight=ft.FontWeight.W_800),
                                    ft.Button("Add Vulnerability", on_click=self.add_vulnerability_prompt)
                                ],
                                alignment=ft.MainAxisAlignment.START,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER
                            ),
                            ft.Row(
                                controls=[
                                    ft.Text("Insert vulnerability on the right, then press the button above.", size=16, weight=ft.FontWeight.W_600),
                                ],
                                alignment=ft.MainAxisAlignment.START,
                            ),
                            ft.Column(
                                spacing=10,
                                margin=10,
                                controls=self.vulnerability_widgets,
                                alignment=ft.MainAxisAlignment.CENTER,
                                horizontal_alignment=ft.CrossAxisAlignment.CENTER
                            )
                        ],
                    ),
                    ft.Row(
                        controls=[
                            ft.Text("Hi!")
                        ]
                    ),
                    self.ivss_editor,
                ]
            )
        )
    